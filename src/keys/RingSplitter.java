package keys;

import bc.KeySaver;
import bc.PemSplitter;
import gui.MyDirectoryChooser;
import gui.MyPGP;
import gui.Text;
import gui.imgs.Icons;
import org.bouncycastle.gpg.keybox.BlobType;
import org.bouncycastle.gpg.keybox.FirstBlob;
import org.bouncycastle.gpg.keybox.KeyBlob;
import org.bouncycastle.gpg.keybox.PublicKeyRingBlob;
import org.bouncycastle.gpg.keybox.bc.BcKeyBox;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;

import javax.swing.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * @author Jose A. Manas
 * @version 24.3.2020
 */
public class RingSplitter {
    private final File ringFile;
    private List<Key> keyList = new ArrayList<>();

    public RingSplitter(File ringFile) {
        this.ringFile = ringFile;
    }

    public void go() {
        if (ringFile.getName().toLowerCase().endsWith(".kbx"))
            loadKbx(ringFile);
        else
            loadRings(ringFile);

        StringBuilder builder = new StringBuilder();
        builder.append("<html>");
        int pkCount = 0;
        int skCount = 0;
        for (Key key : keyList) {
            pkCount++;
            if (key.getSecretKeyList().size() > 0)
                skCount++;
        }
        builder.append(String.format("<p>%s: %d",
                Text.get("public_keys"), pkCount));
        builder.append(String.format("<p>%s: %d",
                Text.get("secret_keys"), skCount));
        int r = JOptionPane.showConfirmDialog(null,
                builder.toString(),
                ringFile.getName(),
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.QUESTION_MESSAGE,
                Icons.getPgpIcon());
        if (r != JFileChooser.APPROVE_OPTION)
            return;
        if (pkCount + skCount == 0)
            return;

        MyDirectoryChooser directoryChooser = new MyDirectoryChooser();
        directoryChooser.setDirectory(Info.getHome());
        Object[] options = {Text.get("accept"), Text.get("cancel")};
        int ret = JOptionPane.showOptionDialog(null,
                directoryChooser,
                Text.get("key_directory"),
                JOptionPane.DEFAULT_OPTION,
                JOptionPane.PLAIN_MESSAGE,
                Icons.getPgpIcon(),
                options, options[0]);
        if (ret != JFileChooser.APPROVE_OPTION)
            return;
        File where = directoryChooser.getSelectedDirectory();
        if (where == null)
            return;

        for (Key key : keyList) {
            if (key.getPublicKeyList().size() > 0)
                KeySaver.exportPublicKey(where, key);
            if (key.getSecretKeyList().size() > 0)
                KeySaver.exportSecretKey(where, key);
        }
    }

    private void loadKbx(File file) {
        try {
            BcKeyBox keyBox = new BcKeyBox(new FileInputStream(file));
            FirstBlob firstBlob = keyBox.getFirstBlob();
            for (KeyBlob keyBlob : keyBox.getKeyBlobs()) {
                if (keyBlob.getType() == BlobType.OPEN_PGP_BLOB) {
                    if (keyBlob instanceof PublicKeyRingBlob) {
                        PublicKeyRingBlob publicKeyRingBlob = (PublicKeyRingBlob) keyBlob;
                        PGPPublicKeyRing publicKeyRing = publicKeyRingBlob.getPGPPublicKeyRing();
                        loadPublicRing(publicKeyRing);
                    } else {
                        System.err.println(keyBlob.getClass().getSimpleName());
                    }
                } else {
                    System.err.println(keyBlob.getType());
                }
            }
        } catch (IOException e) {
            MyPGP.ignore(file.getAbsolutePath());
        }
    }

    private void loadRings(File file) {
        PemSplitter splitter = null;
        try {
            splitter = new PemSplitter(file);
            while (splitter.hasNext()) {
                InputStream decoderStream = PGPUtil.getDecoderStream(splitter.next());
                PGPObjectFactory pgpObjectFactory = new BcPGPObjectFactory(decoderStream);
                for (; ; ) {
                    Object object = pgpObjectFactory.nextObject();
                    if (object == null)
                        break;
                    if (object instanceof PGPPublicKeyRing)
                        loadPublicRing((PGPPublicKeyRing) object);
                    else if (object instanceof PGPSecretKeyRing)
                        loadSecretRing((PGPSecretKeyRing) object);
//                    else
//                        System.out.println(object.getClass().getSimpleName());
                }
            }
        } catch (Exception e) {
            MyPGP.ignore(file.getAbsolutePath());
        } finally {
            if (splitter != null)
                splitter.close();
        }
    }

    private void loadPublicRing(PGPPublicKeyRing ring) {
        Key masterKey = null;
        Iterator keyIterator = ring.getPublicKeys();
        while (keyIterator.hasNext()) {
            PGPPublicKey pgpPublicKey = (PGPPublicKey) keyIterator.next();
            if (pgpPublicKey.isMasterKey())
                masterKey = getMasterKey(pgpPublicKey);
            if (masterKey != null)
                masterKey.add(pgpPublicKey);
        }
    }

    private void loadSecretRing(PGPSecretKeyRing ring) {
        Key masterKey = null;
        Iterator keyIterator = ring.getSecretKeys();
        while (keyIterator.hasNext()) {
            PGPSecretKey pgpSecretKey = (PGPSecretKey) keyIterator.next();
            if (pgpSecretKey.isMasterKey())
                masterKey = getMasterKey(pgpSecretKey);
            if (masterKey != null)
                masterKey.add(pgpSecretKey);
        }
    }

    private Key getMasterKey(PGPPublicKey pgpPublicKey) {
        long id = pgpPublicKey.getKeyID();
        for (Key key : keyList) {
            if (key.getId() == id)
                return key;
        }
        Key masterKey = new Key(pgpPublicKey);
        keyList.add(masterKey);
        return masterKey;
    }

    private Key getMasterKey(PGPSecretKey pgpSecretKey) {
        long id = pgpSecretKey.getKeyID();
        for (Key key : keyList) {
            if (key.getId() == id)
                return key;
        }
        Key masterKey = new Key(pgpSecretKey);
        keyList.add(masterKey);
        return masterKey;
    }
}

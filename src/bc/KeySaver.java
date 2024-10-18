package bc;

import crypto.GetPassword;
import crypto.KeyGenerator;
import exception.MyLogger;
import gui.KeySavePanel;
import gui.Text;
import gui.Version;
import gui.imgs.Icons;
import keys.Key;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;

import javax.swing.*;
import java.io.File;
import java.io.FileOutputStream;

/**
 * @author Jose A. Manas
 * @version 28.9.2014
 */
public class KeySaver {

    public static void exportSecretKey(File where, Key key) {
        FileOutputStream fos = null;
        char[] oldPassword;
        char[] newPassword;
        try {
            oldPassword = GetPassword.getInstance().getDecryptionPassword(key.toString());

            final KeySavePanel panel = new KeySavePanel(key);
            for (; ; ) {
                int result = JOptionPane.showConfirmDialog(null,
                        panel, Text.get("export"),
                        JOptionPane.OK_CANCEL_OPTION,
                        JOptionPane.QUESTION_MESSAGE,
                        Icons.getPgpIcon());
                if (result != JOptionPane.OK_OPTION)
                    return;
                newPassword = panel.getPassword();
                if (newPassword == null)
                    continue;
                break;
            }

            String filename = key.getEmail().replace('@', '_');
            File secFile = new File(where, filename + "_sec.asc");
            fos = new FileOutputStream(secFile);
            ArmoredOutputStream aos = new ArmoredOutputStream(fos);
            addComments(aos, key);

            PBESecretKeyDecryptor oldKeyDecryptor =
                    (new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()))
                            .build(oldPassword);

            PGPDigestCalculator sha256 =
                    new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA256);
            PBESecretKeyEncryptor newKeyEncryptor =
                    (new BcPBESecretKeyEncryptorBuilder(
                            SymmetricKeyAlgorithmTags.AES_256, sha256, KeyGenerator.S2KCOUNT))
                            .build(newPassword);

            for (PGPSecretKey pgpSecretKey0 : key.getSecretKeyList()) {
                PGPSecretKey pgpSecretKey2 = PGPSecretKey.copyWithNewPassword(pgpSecretKey0, oldKeyDecryptor, newKeyEncryptor);
                aos.write(pgpSecretKey2.getEncoded());
            }
            aos.close();
        } catch (Exception e) {
            MyLogger.dump(e, Text.get("export"));
        } finally {
            try {
                if (fos != null)
                    fos.close();
            } catch (Exception ignored) {
            }
        }
    }

    public static void exportPublicKey(File where, Key key) {
        FileOutputStream fos = null;
        try {
            String filename = key.getEmail().replace('@', '_');
            File file = new File(where, filename + "_pub.asc");
            fos = new FileOutputStream(file);
            ArmoredOutputStream aos = new ArmoredOutputStream(fos);
            addComments(aos, key);

            for (PGPPublicKey pgpPublicKey : key.getPublicKeyList())
                aos.write(pgpPublicKey.getEncoded());

            aos.close();
        } catch (Exception e) {
            MyLogger.dump(e, Text.get("export"));
        } finally {
            try {
                if (fos != null)
                    fos.close();
            } catch (Exception ignored) {
            }
        }
    }

    public static void addComments(ArmoredOutputStream aos, Key key) {
        aos.setHeader("Comment", Version.VERSION);
        aos.setHeader("Comment: user-id", key.toString());
        if (key.getKcreation() != null) {
            String validity = key.getKcreation();
            if (key.getKexp() != null)
                validity += " - " + key.getKexp();
            aos.setHeader("Comment: validity", validity);
        }
        aos.setHeader("Comment: id", key.getFingerprintHex4());
    }
}

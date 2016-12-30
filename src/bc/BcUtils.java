package bc;

import gui.MyPGP;
import gui.Text;
import keys.Key;
import keys.KeyDB2;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;

import java.io.IOException;
import java.io.InputStream;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

/**
 * @author Jose A. Manas
 * @version 14.9.2014
 */
class BcUtils {
    static PGPPrivateKey getPrivateKey(PGPSecretKey pgpSecretKey, char[] password) {
        try {
            PBESecretKeyDecryptor decryptor =
                    new BcPBESecretKeyDecryptorBuilder(
                            new BcPGPDigestCalculatorProvider()).
                            build(password);
            return pgpSecretKey.extractPrivateKey(decryptor);
        } catch (PGPException e) {
            MyPGP.getInstance().log2(Text.get("exception.password_needed"));
            return null;
        }
    }

    static PGPEncryptedDataList getEncryptedDataList(InputStream is, String name)
            throws IOException {
        InputStream in = PGPUtil.getDecoderStream(is);
        PGPObjectFactory pgpObjectFactory = new BcPGPObjectFactory(in);
        for (; ; ) {
            Object x = pgpObjectFactory.nextObject();
            if (x == null) {
                log2(String.format("%s: %s", name, Text.get("exception.bad_format")));
                return null;
            }
            // the first object might be a PGP marker packet.
            if (x instanceof PGPEncryptedDataList)
                return (PGPEncryptedDataList) x;
        }
    }

    static List<PGPPublicKeyEncryptedData> getKnownKeyEncryptedData(PGPEncryptedDataList encryptedDataList) {
        List<PGPPublicKeyEncryptedData> list = new ArrayList<>();
        Iterator it = encryptedDataList.getEncryptedDataObjects();
        while (it.hasNext()) {
            Object next = it.next();
            if (!(next instanceof PGPPublicKeyEncryptedData)) {
                MyPGP.getInstance().log2("unexpected packet: " + next.getClass().getSimpleName());
                continue;
            }
            PGPPublicKeyEncryptedData item = (PGPPublicKeyEncryptedData) next;
            long id = item.getKeyID();
            Key key = KeyDB2.getInstance().getKey(id);
            if (key == null) {
                log2(String.format("%s: %s", Text.get("encrypted_for"), Key.mkId8(id)));
            } else {
                log2(String.format("%s: %s", Text.get("encrypted_for"), key));
                PGPSecretKey pgpSecretKey = KeyDB2.getInstance().getSecretKey(id);
                if (pgpSecretKey != null)
                    list.add(item);
            }
        }
        return list;
    }

    static void verifySignature(PGPOnePassSignatureList onePassSignatureList, PGPSignatureList signatureList,
                                byte[] redBytes)
            throws PGPException {
        if (onePassSignatureList == null || signatureList == null) {
            log2(Text.get("signers_none"));
            return;
        }
        if (onePassSignatureList.isEmpty() || signatureList.isEmpty()) {
            log2(Text.get("signers_none"));
            return;
        }

        PGPOnePassSignature ops = onePassSignatureList.get(0);
        int signAlgo = ops.getKeyAlgorithm();
        int hashAlgo = ops.getHashAlgorithm();
        log2(String.format("%s: %s(%s)", Text.get("signature"), ToString.publicKey(signAlgo), ToString.hash(hashAlgo)));

        Key key = KeyDB2.getInstance().getKey(ops.getKeyID());
        if (key == null) {
            log2(String.format("%s: %s", Text.get("signer"), Key.mkId8(ops.getKeyID())));
            return;
        }
        log2(String.format("%s: %s", Text.get("signer"), key));
        PGPPublicKey publicKey = key.getPublicKey();
        ops.init(new JcaPGPContentVerifierBuilderProvider()
                        .setProvider("BC"),
                publicKey);
        ops.update(redBytes);

        PGPSignature signature = signatureList.get(0);
        logSignTime(signature);

        if (ops.verify(signature)) {
//                    Iterator<?> userIds = publicKey.getUserIDs();
//                    while (userIds.hasNext()) {
//                        String userId = (String) userIds.next();
//                        log2(String.format("%s: %s ", Text.get("signer"), userId));
//                    }
            log2(Text.get("signature_ok"));
        } else {
            log2(Text.get("signature_bad"));
        }
    }

    static void logSignTime(PGPSignature signature) {
        Date creationTime = signature.getCreationTime();
        if (creationTime != null) {
//            SimpleDateFormat sdf = new SimpleDateFormat("H:mm:ss d.M.yyyy");
            SimpleDateFormat sdf = new SimpleDateFormat("E, d MMM yyyy; H:mm:ss", Text.getLocale());
            BcUtils.log2(String.format("%s: %s", Text.get("signature"), sdf.format(creationTime)));
        }
    }

    static void log1(String msg) {
        MyPGP.getInstance().log1(msg);
    }

    static void log2(String msg) {
        MyPGP.getInstance().log2(msg);
    }
}

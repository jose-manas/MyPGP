package bc;

import crypto.GetPassword;
import exception.PasswordCancelled;
import gui.MyPGP;
import gui.Text;
import gui.Version;
import gui.imgs.Icons;
import keys.Key;
import keys.KeyDB2;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.*;

import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * @author Jose A. Manas
 * @version 17.8.2014
 */
public class BcUtilsFiles {
    private static final int BUFFER_SIZE = 1 << 16;

    public static void encrypt(File redFile, List<Key> publicKeys)
            throws Exception {
        int encryptAlgo = AlgorithmSelection.getEncryptAlgo(publicKeys);
        MyPGP.getInstance().log2(Text.get("encrypt") + ": " + ToString.symmetricKey(encryptAlgo));
        int compressionAlgo = AlgorithmSelection.getCompressionAlgo(publicKeys);

        boolean armor = true;
        boolean withIntegrityCheck = true;

        File blackFile = null;
        OutputStream out = null;
        try {
            blackFile = mkFile(redFile, ".asc");
            if (blackFile == null)
                return;
            OutputStream os = new BufferedOutputStream(new FileOutputStream(blackFile));
            out = os;
            if (armor) {
                ArmoredOutputStream aos = new ArmoredOutputStream(os);
                aos.setHeader("Comment", Version.VERSION);
                out = aos;
            }

            JcePGPDataEncryptorBuilder encryptorBuilder =
                    new JcePGPDataEncryptorBuilder(encryptAlgo)
                            .setWithIntegrityPacket(withIntegrityCheck)
                            .setSecureRandom(new SecureRandom())
                            .setProvider("BC");
            PGPEncryptedDataGenerator encryptedDataGenerator =
                    new PGPEncryptedDataGenerator(encryptorBuilder);

            for (Key key : publicKeys) {
                PGPPublicKey encryptingKey = key.getEncryptingKey();
                JcePublicKeyKeyEncryptionMethodGenerator keyEncryptionMethodGenerator =
                        new JcePublicKeyKeyEncryptionMethodGenerator(encryptingKey)
                                .setProvider("BC");
                encryptedDataGenerator.addMethod(keyEncryptionMethodGenerator);
            }

            OutputStream encryptedData = encryptedDataGenerator.open(out, new byte[BUFFER_SIZE]);
            PGPCompressedDataGenerator compressedDataGenerator =
                    new PGPCompressedDataGenerator(compressionAlgo);
            OutputStream compressedOut = compressedDataGenerator.open(encryptedData);

            PGPLiteralDataGenerator literalDataGenerator =
                    new PGPLiteralDataGenerator();
            OutputStream literalOut = literalDataGenerator.open(compressedOut,
                    PGPLiteralData.BINARY,
                    redFile.getName(),
                    new Date(redFile.lastModified()),
                    new byte[BUFFER_SIZE]);
            {
                byte[] buffer = new byte[BUFFER_SIZE];
                InputStream redIs = new BufferedInputStream(new FileInputStream(redFile));
                for (; ; ) {
                    int n = redIs.read(buffer);
                    if (n < 0)
                        break;
                    literalOut.write(buffer, 0, n);
                }
                redIs.close();
            }
            literalOut.close();

            compressedOut.close();
            compressedDataGenerator.close();
            encryptedData.close();
            encryptedDataGenerator.close();

            close(out);
        } catch (Exception e) {
            forget(blackFile, out);
            throw e;

//        } finally {
//            close(out);
//            close(os);
        }
    }

    public static void sign(File inFile, Key signerKey, char[] password)
            throws Exception {
        boolean armor = false;

        File outFile = null;
        OutputStream out = null;
        try {
            PGPSecretKey secretKey = signerKey.getSigningKey();
            PGPPublicKey publicKey = secretKey.getPublicKey();
            PGPPrivateKey privateKey = BcUtils.getPrivateKey(secretKey, password);
            if (privateKey == null)
                return;

            outFile = mkFile(inFile, ".sig");
            OutputStream os = new BufferedOutputStream(new FileOutputStream(outFile));
            out = os;
            if (armor) {
                ArmoredOutputStream aos = new ArmoredOutputStream(os);
                aos.setHeader("Comment", Version.VERSION);
                out = aos;
            }

            int signAlgo = publicKey.getAlgorithm();
            int hashAlgo = AlgorithmSelection.getHashAlgo(signerKey);
            MyPGP.getInstance().log2(String.format("%s: %s(%s)",
                    signerKey,
                    ToString.publicKey(signAlgo),
                    ToString.hash(hashAlgo)));

            JcaPGPContentSignerBuilder contentSignerBuilder =
                    new JcaPGPContentSignerBuilder(signAlgo, hashAlgo)
                            .setProvider("BC");
            PGPSignatureGenerator signatureGenerator =
                    new PGPSignatureGenerator(contentSignerBuilder);
            signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);

            byte[] buffer = new byte[BUFFER_SIZE];
            InputStream is = new BufferedInputStream(new FileInputStream(inFile));
            for (; ; ) {
                int n = is.read(buffer);
                if (n < 0)
                    break;
                signatureGenerator.update(buffer, 0, n);
            }
            is.close();

            BCPGOutputStream bOut = new BCPGOutputStream(out);
            signatureGenerator.generate().encode(bOut);
            bOut.close();

            close(out);
        } catch (Exception e) {
            forget(outFile, out);
            throw e;

//        } finally {
//            close(out);
//            close(os);
        }
    }

    public static void sign(File inFile,
                            List<Key> signerKeyList,
                            Map<Key, char[]> passwords)
            throws Exception {
        boolean armor = false;

        File outFile = null;
        OutputStream out = null;
        try {
            PGPPublicKey[] publicKeys = new PGPPublicKey[signerKeyList.size()];
            PGPPrivateKey[] privateKeys = new PGPPrivateKey[signerKeyList.size()];
            for (int i = 0; i < signerKeyList.size(); i++) {
                Key signerKey = signerKeyList.get(i);
                char[] password = passwords.get(signerKey);
                PGPSecretKey secretKey = signerKey.getSigningKey();
                PGPPublicKey publicKey = secretKey.getPublicKey();
                PGPPrivateKey privateKey = BcUtils.getPrivateKey(secretKey, password);
                if (privateKey == null)
                    return;
                publicKeys[i] = publicKey;
                privateKeys[i] = privateKey;
            }

            outFile = mkFile(inFile, ".sig");
            OutputStream os = new BufferedOutputStream(new FileOutputStream(outFile));
            out = os;
            if (armor) {
                ArmoredOutputStream aos = new ArmoredOutputStream(os);
                aos.setHeader("Comment", Version.VERSION);
                out = aos;
            }
            BCPGOutputStream bOut = new BCPGOutputStream(out);

            for (int i = 0; i < signerKeyList.size(); i++) {
                Key signerKey = signerKeyList.get(i);
                PGPPublicKey publicKey = publicKeys[i];
                PGPPrivateKey privateKey = privateKeys[i];

                int signAlgo = publicKey.getAlgorithm();
                int hashAlgo = AlgorithmSelection.getHashAlgo(signerKey);
                MyPGP.getInstance().log2(String.format("%s: %s(%s)",
                        signerKey,
                        ToString.publicKey(signAlgo),
                        ToString.hash(hashAlgo)));

                JcaPGPContentSignerBuilder contentSignerBuilder =
                        new JcaPGPContentSignerBuilder(signAlgo, hashAlgo)
                                .setProvider("BC");
                PGPSignatureGenerator signatureGenerator =
                        new PGPSignatureGenerator(contentSignerBuilder);
                signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);

                byte[] buffer = new byte[BUFFER_SIZE];
                InputStream is = new BufferedInputStream(new FileInputStream(inFile));
                for (; ; ) {
                    int n = is.read(buffer);
                    if (n < 0)
                        break;
                    signatureGenerator.update(buffer, 0, n);
                }
                is.close();

                signatureGenerator.generate().encode(bOut);
            }
            bOut.close();

            close(out);
        } catch (Exception e) {
            forget(outFile, out);
            throw e;

//        } finally {
//            close(out);
//            close(os);
        }
    }

//    public static void encrypt_sign(File redFile, Key signerKey, List<Key> publicKeys, char[] password)
//            throws IOException, PGPException {
//        int encryptAlgo = AlgorithmSelection.getEncryptAlgo(publicKeys);
//        MyPGP.getInstance().log2(Text.get("encrypt") + ": " + ToString.symmetricKey(encryptAlgo));
//        int compressionAlgo = AlgorithmSelection.getCompressionAlgo(publicKeys);
//
//        boolean armor = true;
//        boolean withIntegrityCheck = true;
//
//        OutputStream os = null;
//        OutputStream out = null;
//        try {
//            PGPSecretKey secretKey = signerKey.getSigningKey();
//            PGPPublicKey publicKey = secretKey.getPublicKey();
//            PGPPrivateKey privateKey = BcUtils.getPrivateKey(secretKey, password);
//            if (privateKey == null)
//                return;
//
//            File blackFile = mkFile(redFile, ".asc");
//            if (blackFile == null)
//                return;
//            os = new BufferedOutputStream(new FileOutputStream(blackFile));
//            out = os;
//            if (armor) {
//                ArmoredOutputStream aos = new ArmoredOutputStream(os);
//                aos.setHeader("Comment", Version.VERSION);
//                out = aos;
//            }
//
//            JcePGPDataEncryptorBuilder encryptorBuilder =
//                    new JcePGPDataEncryptorBuilder(encryptAlgo)
//                            .setWithIntegrityPacket(withIntegrityCheck)
//                            .setSecureRandom(new SecureRandom())
//                            .setProvider("BC");
//            PGPEncryptedDataGenerator encryptedDataGenerator =
//                    new PGPEncryptedDataGenerator(encryptorBuilder);
//
//            for (Key key : publicKeys) {
//                PGPPublicKey encryptingKey = key.getEncryptingKey();
//                JcePublicKeyKeyEncryptionMethodGenerator keyEncryptionMethodGenerator =
//                        new JcePublicKeyKeyEncryptionMethodGenerator(encryptingKey)
//                                .setProvider("BC");
//                encryptedDataGenerator.addMethod(keyEncryptionMethodGenerator);
//            }
//
//            OutputStream encryptedData = encryptedDataGenerator.open(out, new byte[BUFFER_SIZE]);
//            PGPCompressedDataGenerator compressedDataGenerator =
//                    new PGPCompressedDataGenerator(compressionAlgo);
//            OutputStream compressedOut = compressedDataGenerator.open(encryptedData);
//
//            int signAlgo = publicKey.getAlgorithm();
//            int hashAlgo = AlgorithmSelection.getHashAlgo(signerKey);
//            MyPGP.getInstance().log2(String.format("%s: %s(%s)",
//                    signerKey,
//                    ToString.publicKey(signAlgo),
//                    ToString.hash(hashAlgo)));
//
//            JcaPGPContentSignerBuilder contentSignerBuilder =
//                    new JcaPGPContentSignerBuilder(signAlgo, hashAlgo)
//                            .setProvider("BC");
//            PGPSignatureGenerator signatureGenerator =
//                    new PGPSignatureGenerator(contentSignerBuilder);
//            signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);
//
//            Iterator it = publicKey.getUserIDs();
//            if (it.hasNext()) {
//                String userId = (String) it.next();
//                PGPSignatureSubpacketGenerator signatureSubpacketGenerator =
//                        new PGPSignatureSubpacketGenerator();
//                signatureSubpacketGenerator.setSignerUserID(false, userId);
//                signatureGenerator.setHashedSubpackets(signatureSubpacketGenerator.generate());
//            }
//            signatureGenerator.generateOnePassVersion(false).encode(compressedOut);
//
//            PGPLiteralDataGenerator literalDataGenerator =
//                    new PGPLiteralDataGenerator();
//            OutputStream literalOut = literalDataGenerator.open(compressedOut,
//                    PGPLiteralData.BINARY,
//                    redFile.getName(),
//                    new Date(blackFile.lastModified()),
//                    new byte[BUFFER_SIZE]);
//
//            {
//                byte[] buffer = new byte[BUFFER_SIZE];
//                InputStream redIs = new BufferedInputStream(new FileInputStream(redFile));
//                for (; ; ) {
//                    int n = redIs.read(buffer);
//                    if (n < 0)
//                        break;
//                    literalOut.write(buffer, 0, n);
//                    signatureGenerator.update(buffer, 0, n);
//                }
//                redIs.close();
//            }
//            literalOut.close();
//            literalDataGenerator.close();
//            signatureGenerator.generate().encode(compressedOut);
//
//            compressedOut.close();
//            compressedDataGenerator.close();
//            encryptedData.close();
//            encryptedDataGenerator.close();
//        } finally {
//            close(out);
//            close(os);
//        }
//    }

    public static void encrypt_sign(File redFile,
                                    List<Key> signerKeyList,
                                    List<Key> encryptingKeys,
                                    Map<Key, char[]> passwords)
            throws Exception {
        int encryptAlgo = AlgorithmSelection.getEncryptAlgo(encryptingKeys);
        MyPGP.getInstance().log2(Text.get("encrypt") + ": " + ToString.symmetricKey(encryptAlgo));
        int compressionAlgo = AlgorithmSelection.getCompressionAlgo(encryptingKeys);

        boolean armor = true;
        boolean withIntegrityCheck = true;

        File blackFile = null;
        OutputStream out = null;
        try {
            PGPPublicKey[] publicKeys = new PGPPublicKey[signerKeyList.size()];
            PGPPrivateKey[] privateKeys = new PGPPrivateKey[signerKeyList.size()];
            for (int i = 0; i < signerKeyList.size(); i++) {
                Key signerKey = signerKeyList.get(i);
                char[] password = passwords.get(signerKey);
                PGPSecretKey secretKey = signerKey.getSigningKey();
                PGPPublicKey publicKey = secretKey.getPublicKey();
                PGPPrivateKey privateKey = BcUtils.getPrivateKey(secretKey, password);
                if (privateKey == null)
                    return;
                publicKeys[i] = publicKey;
                privateKeys[i] = privateKey;
            }

            blackFile = mkFile(redFile, ".asc");
            if (blackFile == null)
                return;
            OutputStream os = new BufferedOutputStream(new FileOutputStream(blackFile));
            out = os;
            if (armor) {
                ArmoredOutputStream aos = new ArmoredOutputStream(os);
                aos.setHeader("Comment", Version.VERSION);
                out = aos;
            }

            JcePGPDataEncryptorBuilder encryptorBuilder =
                    new JcePGPDataEncryptorBuilder(encryptAlgo)
                            .setWithIntegrityPacket(withIntegrityCheck)
                            .setSecureRandom(new SecureRandom())
                            .setProvider("BC");
            PGPEncryptedDataGenerator encryptedDataGenerator =
                    new PGPEncryptedDataGenerator(encryptorBuilder);

            for (Key key : encryptingKeys) {
                PGPPublicKey encryptingKey = key.getEncryptingKey();
                JcePublicKeyKeyEncryptionMethodGenerator keyEncryptionMethodGenerator =
                        new JcePublicKeyKeyEncryptionMethodGenerator(encryptingKey)
                                .setProvider("BC");
                encryptedDataGenerator.addMethod(keyEncryptionMethodGenerator);
            }

            OutputStream encryptedData = encryptedDataGenerator.open(out, new byte[BUFFER_SIZE]);
            PGPCompressedDataGenerator compressedDataGenerator =
                    new PGPCompressedDataGenerator(compressionAlgo);
            OutputStream compressedOut = compressedDataGenerator.open(encryptedData);

            for (int i = 0; i < signerKeyList.size(); i++) {
                Key signerKey = signerKeyList.get(i);
                PGPPublicKey publicKey = publicKeys[i];
                PGPPrivateKey privateKey = privateKeys[i];

                int signAlgo = publicKey.getAlgorithm();
                int hashAlgo = AlgorithmSelection.getHashAlgo(signerKey);
                MyPGP.getInstance().log2(String.format("%s: %s(%s)",
                        signerKey,
                        ToString.publicKey(signAlgo),
                        ToString.hash(hashAlgo)));

                JcaPGPContentSignerBuilder contentSignerBuilder =
                        new JcaPGPContentSignerBuilder(signAlgo, hashAlgo)
                                .setProvider("BC");
                PGPSignatureGenerator signatureGenerator =
                        new PGPSignatureGenerator(contentSignerBuilder);
                signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);

                Iterator it = publicKey.getUserIDs();
                if (it.hasNext()) {
                    String userId = (String) it.next();
                    PGPSignatureSubpacketGenerator signatureSubpacketGenerator =
                            new PGPSignatureSubpacketGenerator();
                    signatureSubpacketGenerator.setSignerUserID(false, userId);
                    signatureGenerator.setHashedSubpackets(signatureSubpacketGenerator.generate());
                }
                signatureGenerator.generateOnePassVersion(false).encode(compressedOut);

                PGPLiteralDataGenerator literalDataGenerator =
                        new PGPLiteralDataGenerator();
                OutputStream literalOut = literalDataGenerator.open(compressedOut,
                        PGPLiteralData.BINARY,
                        redFile.getName(),
                        new Date(blackFile.lastModified()),
                        new byte[BUFFER_SIZE]);

                {
                    byte[] buffer = new byte[BUFFER_SIZE];
                    InputStream redIs = new BufferedInputStream(new FileInputStream(redFile));
                    for (; ; ) {
                        int n = redIs.read(buffer);
                        if (n < 0)
                            break;
                        literalOut.write(buffer, 0, n);
                        signatureGenerator.update(buffer, 0, n);
                    }
                    redIs.close();
                }
                literalOut.close();
                literalDataGenerator.close();
                signatureGenerator.generate().encode(compressedOut);
            }

            compressedOut.close();
            compressedDataGenerator.close();
            encryptedData.close();
            encryptedDataGenerator.close();

            close(out);
        } catch (Exception e) {
            forget(blackFile, out);
            throw e;

        } finally {
//            close(out);
//            close(os);
        }
    }

    private static void decrypt(File redFile, File blackFile, Map<Long, char[]> passwords)
            throws IOException, PasswordCancelled, PGPException {
        BcUtils.log1(String.format("%s(%s) --> %s",
                Text.get("decrypt"), blackFile.getName(), redFile.getName()));

        InputStream is = null;
        try {
            is = CRLF.sanitize(new FileInputStream(blackFile));
            PGPEncryptedDataList encryptedDataList = BcUtils.getEncryptedDataList(is, blackFile.getName());
            if (encryptedDataList == null)
                return;

            List<PGPPublicKeyEncryptedData> list = BcUtils.getKnownKeyEncryptedData(encryptedDataList);
            if (list.size() == 0) {
                BcUtils.log2(Text.get("no_known_key"));
                return;
            }

            PGPPrivateKey sKey = null;
            PGPPublicKeyEncryptedData pbe = null;
            for (PGPPublicKeyEncryptedData item : list) {
                pbe = item;
                long id = pbe.getKeyID();
                Key key = KeyDB2.getInstance().getKey(id);
                if (key == null)
                    continue;
                char[] password = passwords.get(id);
                if (password == null)
                    password = GetPassword.getInstance().getDecryptionPassword(Text.get("decrypt") + ": " + key);
                if (password == null || password.length == 0)
                    continue;
                passwords.put(id, password);
                PGPSecretKey pgpSecretKey = KeyDB2.getInstance().getSecretKey(id);
                sKey = BcUtils.getPrivateKey(pgpSecretKey, password);
                if (sKey != null)
                    break;
            }
            if (sKey == null) {
                BcUtils.log2(Text.get("no_known_key"));
                return;
            }

            PGPOnePassSignatureList onePassSignatureList = null;
            PGPSignatureList signatureList = null;

            PublicKeyDataDecryptorFactory factory =
                    new JcePublicKeyDataDecryptorFactoryBuilder()
                            .setProvider("BC")
                            .build(sKey);
            int encryptAlgo = pbe.getSymmetricAlgorithm(factory);
            MyPGP.getInstance().log2(Text.get("decrypt") + ": " + ToString.symmetricKey(encryptAlgo));
            InputStream clear = pbe.getDataStream(factory);
            PGPObjectFactory pgpObjectFactory = new BcPGPObjectFactory(clear);

            ByteArrayOutputStream redData = new ByteArrayOutputStream();
            for (; ; ) {
                Object message = pgpObjectFactory.nextObject();
                if (message == null)
                    break;
                if (message instanceof PGPCompressedData) {
                    PGPCompressedData compressedData = (PGPCompressedData) message;
                    pgpObjectFactory = new BcPGPObjectFactory(compressedData.getDataStream());
                } else if (message instanceof PGPLiteralData) {
                    PGPLiteralData literalData = (PGPLiteralData) message;
                    pipeAll(literalData.getInputStream(), redData);
                } else if (message instanceof PGPOnePassSignatureList) {
                    onePassSignatureList = (PGPOnePassSignatureList) message;
                } else if (message instanceof PGPSignatureList) {
                    signatureList = (PGPSignatureList) message;
                } else {
                    throw new PGPException("message unknown message type.");
                }
            }
            redData.close();
            byte[] redBytes = redData.toByteArray();

            if (pbe.isIntegrityProtected() && !pbe.verify())
                BcUtils.log2("integrity check fails");

            OutputStream redOs = null;
            try {
                redOs = new BufferedOutputStream(new FileOutputStream(redFile));
                redOs.write(redBytes);
            } finally {
                close(redOs);
            }

            BcUtils.verifySignature(onePassSignatureList, signatureList, redBytes);
        } finally {
            close(is);
        }
    }

    public static void verify(File signatureFile, File redFile)
            throws IOException, PGPException {
        InputStream sigIs = null;
        try {
            sigIs = new FileInputStream(signatureFile);
            InputStream decoderStream = PGPUtil.getDecoderStream(sigIs);
            PGPObjectFactory pgpObjectFactory = new BcPGPObjectFactory(decoderStream);

            PGPSignatureList signatureList;
            Object object = pgpObjectFactory.nextObject();
            if (object instanceof PGPCompressedData) {
                PGPCompressedData compressedData = (PGPCompressedData) object;
                pgpObjectFactory = new BcPGPObjectFactory(compressedData.getDataStream());
                signatureList = (PGPSignatureList) pgpObjectFactory.nextObject();
            } else {
                signatureList = (PGPSignatureList) object;
            }

            for (int i = 0; i < signatureList.size(); i++) {
                PGPSignature signature = signatureList.get(i);
                verify(redFile, signature);
            }
        } finally {
            close(sigIs);
        }
    }

    private static void verify(PGPSignatureList signatureList, File redFile)
            throws IOException, PGPException {
        for (int i = 0; i < signatureList.size(); i++) {
            PGPSignature signature = signatureList.get(i);
            verify(redFile, signature);
        }
    }

    private static void verify(File redFile, PGPSignature signature)
            throws PGPException, IOException {
        int hashAlgo = signature.getHashAlgorithm();
        int signAlgo = signature.getKeyAlgorithm();
        BcUtils.log2(String.format("%s: %s(%s)", Text.get("signature"), ToString.publicKey(signAlgo), ToString.hash(hashAlgo)));
        BcUtils.logSignTime(signature);

        Key key = KeyDB2.getInstance().getKey(signature.getKeyID());
        if (key == null) {
            BcUtils.log2(String.format("%s: %s", Text.get("signer"), Key.mkId8(signature.getKeyID())));
            return;
        }
        BcUtils.log2(String.format("%s: %s", Text.get("signer"), key));

        PGPPublicKey publicKey = key.getPublicKey();
        signature.init(
                new JcaPGPContentVerifierBuilderProvider()
                        .setProvider("BC"),
                publicKey);
        {
            byte[] buffer = new byte[BUFFER_SIZE];
            InputStream redIs = new BufferedInputStream(new FileInputStream(redFile));
            for (; ; ) {
                int n = redIs.read(buffer);
                if (n < 0)
                    break;
                signature.update(buffer, 0, n);
            }
            redIs.close();
        }
        if (signature.verify())
            BcUtils.log2(Text.get("signature_ok"));
        else
            BcUtils.log2(Text.get("signature_bad"));
    }

    public static void process(File blackFile, Map<Long, char[]> passwords)
            throws IOException, PasswordCancelled, PGPException, SignatureException {
        InputStream is = null;
        try {
            Object x;
            is = CRLF.sanitize(new FileInputStream(blackFile));
            InputStream decoderStream = PGPUtil.getDecoderStream(is);
            PGPObjectFactory pgpObjectFactory = new BcPGPObjectFactory(decoderStream);
            do {
                try {
                    x = pgpObjectFactory.nextObject();
                } catch (Exception e) {
                    x = null;
                }
                if (x == null) {
                    BcUtils.log1(String.format("%s(%s) :",
                            Text.get("process"), blackFile.getName()));
                    BcUtils.log2(String.format("%s: %s", blackFile.getName(), Text.get("exception.bad_format")));
                    return;
                }
                if (x instanceof PGPCompressedData) {
                    PGPCompressedData compressedData = (PGPCompressedData) x;
                    pgpObjectFactory = new BcPGPObjectFactory(compressedData.getDataStream());
                    x = pgpObjectFactory.nextObject();
                }
            } while (x instanceof PGPMarker);

            if (x instanceof PGPEncryptedDataList) {
                File redFile = mkRedFile(blackFile);
                if (redFile == null)
                    redFile = new File(blackFile.getParent(), "mypgp.out");
                decrypt(redFile, blackFile, passwords);
                return;
            }

            if (x instanceof PGPSignatureList) {
                File redFile = mkRedFile(blackFile);
                String filenameString = redFile == null ? "no" : redFile.getName();
                BcUtils.log1(String.format("%s == %s(%s) :",
                        blackFile.getName(), Text.get("signature"), filenameString));
                if (redFile == null)
                    BcUtils.log2(String.format("%s: %s", blackFile.getName(), Text.get("no_signed_file")));
                else
                    verify((PGPSignatureList) x, redFile);
                return;
            }

            if (x instanceof PGPOnePassSignatureList) {
                BcUtils.log1(String.format("%s(%s) :",
                        Text.get("signature"), blackFile.getName()));
                PGPOnePassSignatureList onePassSignatureList = (PGPOnePassSignatureList) x;

                PGPLiteralData literalData = (PGPLiteralData) pgpObjectFactory.nextObject();
                String filename = literalData.getFileName();
                Date date = literalData.getModificationTime();
                ByteArrayOutputStream redData = new ByteArrayOutputStream();
                pipeAll(literalData.getInputStream(), redData);
                redData.close();
                byte[] redBytes = redData.toByteArray();

                if (filename != null) {
                    if (date == null || date.getTime() == 0)
                        BcUtils.log2("-> " + filename);
                    else
                        BcUtils.log2(String.format("-> %s (%tF)", filename, date));
                    File redFile = new File(blackFile.getParent(), filename);
                    if (redFile.exists())
                        redFile = new File(blackFile.getParent(), "mypgp.out");
                    OutputStream os = new FileOutputStream(redFile);
                    os.write(redBytes);
                    os.close();
                }

                PGPSignatureList signatureList = (PGPSignatureList) pgpObjectFactory.nextObject();
                BcUtils.verifySignature(onePassSignatureList, signatureList, redBytes);
                return;
            }

            if (x instanceof PGPPublicKey)
                BcUtils.log2(String.format("%s: %s", blackFile.getName(), x.getClass().getSimpleName()));
            else if (x instanceof PGPPublicKeyRing)
                BcUtils.log2(String.format("%s: %s", blackFile.getName(), x.getClass().getSimpleName()));
            else if (x instanceof PGPPublicKeyRingCollection)
                BcUtils.log2(String.format("%s: %s", blackFile.getName(), x.getClass().getSimpleName()));

            else if (x instanceof PGPSecretKey)
                BcUtils.log2(String.format("%s: %s", blackFile.getName(), x.getClass().getSimpleName()));
            else if (x instanceof PGPSecretKeyRing)
                BcUtils.log2(String.format("%s: %s", blackFile.getName(), x.getClass().getSimpleName()));
            else if (x instanceof PGPSecretKeyRingCollection)
                BcUtils.log2(String.format("%s: %s", blackFile.getName(), x.getClass().getSimpleName()));

            else
                BcUtils.log2(String.format("%s: %s", blackFile.getName(), x.getClass().getSimpleName()));
        } finally {
            close(is);
        }
    }

    private static File mkFile(File base, String ext) {
        FilePanel panel = new FilePanel(base, ext);
        File file = panel.getOvwFile();
        if (!file.exists())
            return file;

        int ret = JOptionPane.showConfirmDialog(null,
                panel, "",
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.QUESTION_MESSAGE,
                Icons.getPgpIcon());
        if (ret != JOptionPane.OK_OPTION)
            return null;
        return panel.getSelectedFile();
    }

    private static File mkRedFile(File blackFile) {
        String redFilename;
        String blackFilename = blackFile.getName();
        if (blackFilename.endsWith(".asc"))
            redFilename = blackFilename.substring(0, blackFilename.length() - 4);
        else if (blackFilename.endsWith(".sig"))
            redFilename = blackFilename.substring(0, blackFilename.length() - 4);
        else if (blackFilename.endsWith(".pgp"))
            redFilename = blackFilename.substring(0, blackFilename.length() - 4);
        else if (blackFilename.endsWith(".gpg"))
            redFilename = blackFilename.substring(0, blackFilename.length() - 4);
        else
            return null;

        File file = new File(blackFile.getParent(), redFilename);
        if (!file.exists())
            return file;

        FilePanel panel = new FilePanel(file);
        int ret = JOptionPane.showConfirmDialog(null,
                panel, "",
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.QUESTION_MESSAGE,
                Icons.getPgpIcon());
        if (ret != JOptionPane.OK_OPTION)
            return null;
        return panel.getSelectedFile();
    }

    public static void pipeAll(InputStream is, OutputStream os)
            throws IOException {
        byte[] buffer = new byte[BUFFER_SIZE];
        for (; ; ) {
            int n = is.read(buffer);
            if (n < 0)
                break;
            os.write(buffer, 0, n);
        }
    }

    private static void close(InputStream is) {
        if (is == null)
            return;
        try {
            is.close();
        } catch (Exception ignored) {
        }
    }

    private static void close(OutputStream os) {
        if (os == null)
            return;
        try {
            os.close();
        } catch (Exception ignored) {
        }
    }

    private static void forget(File file, OutputStream os) {
        try {
            os.close();
        } catch (Exception ignored) {
        }
        try {
            //noinspection ResultOfMethodCallIgnored
            file.delete();
        } catch (Exception ignored) {
        }
    }

    private static class FilePanel
            extends JPanel {
        private JCheckBox box1;
        private JCheckBox box2;
        private final File ovwFile;
        private File newFile;

        public FilePanel(File file) {
            String base = file.getName();
            String ext = "out";
            String fileName = file.getName();
            int dot = fileName.lastIndexOf('.');
            if (dot > 0) {
                base = fileName.substring(0, dot);
                ext = fileName.substring(dot+1);
            }
            ovwFile = file;
            newFile = ovwFile;
            int v = 2;
            while (newFile.exists()) {
                newFile = new File(
                        file.getParent(),
                        String.format("%s_%d%s", base, v++, ext));
            }

            setup();
        }

        public FilePanel(File base, String ext) {
            ovwFile = new File(base.getParent(), base.getName() + ext);
            newFile = ovwFile;
            int v = 2;
            while (newFile.exists()) {
                newFile = new File(
                        base.getParent(),
                        String.format("%s_%d%s", base.getName(), v++, ext));
            }

            setup();
        }

        private void setup() {
            setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
            ButtonGroup group = new ButtonGroup();
            box1 = new JCheckBox(Text.get("overwrite") + ": " + ovwFile);
            box2 = new JCheckBox(Text.get("new") + ": " + newFile);
            group.add(box1);
            group.add(box2);
            box1.setSelected(true);

            box1.setAlignmentX(Component.LEFT_ALIGNMENT);
            box2.setAlignmentX(Component.LEFT_ALIGNMENT);
            add(box1);
            add(box2);
        }

        public File getOvwFile() {
            return ovwFile;
        }

        public File getSelectedFile() {
            if (box1.isSelected())
                return ovwFile;
            else
                return newFile;
        }
    }
}

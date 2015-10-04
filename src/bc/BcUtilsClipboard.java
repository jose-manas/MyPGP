package bc;

import crypto.GetPassword;
import exception.PasswordCancelled;
import gui.MyPGP;
import gui.Text;
import gui.Version;
import keys.Key;
import keys.KeyDB2;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.*;

import java.io.*;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

/**
 * @author Jose A. Manas
 * @version 17.8.2014
 */
public class BcUtilsClipboard {
    private static final int BUFFER_SIZE = 1 << 16;

    public static String encrypt(String redText, List<Key> publicKeys)
            throws IOException, PGPException {
        int encryptAlgo = AlgorithmSelection.getEncryptAlgo(publicKeys);
        MyPGP.getInstance().log2(Text.get("encrypt") + ": " + ToString.symmetricKey(encryptAlgo));
        int compressionAlgo = AlgorithmSelection.getCompressionAlgo(publicKeys);

        boolean armor = true;
        boolean withIntegrityCheck = true;
        byte[] redBytes = redText.getBytes("UTF-8");

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        OutputStream out = baos;
        if (armor) {
            ArmoredOutputStream aos = new ArmoredOutputStream(baos);
            aos.setHeader("Comment", Version.VERSION);
            out = aos;
        }

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPCompressedDataGenerator comData =
                new PGPCompressedDataGenerator(compressionAlgo);
        PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
        OutputStream pOut = literalDataGenerator.open(
                comData.open(bOut),
                PGPLiteralData.BINARY,
                "clip",
                redBytes.length,
                new Date());
        pOut.write(redBytes);
        comData.close();
        byte[] blackBytes = bOut.toByteArray();

        JcePGPDataEncryptorBuilder encryptorBuilder =
                new JcePGPDataEncryptorBuilder(encryptAlgo)
                        .setWithIntegrityPacket(withIntegrityCheck)
                        .setSecureRandom(new SecureRandom())
                        .setProvider("BC");
        PGPEncryptedDataGenerator encryptedDataGenerator =
                new PGPEncryptedDataGenerator(encryptorBuilder);

        for (Key key : publicKeys) {
            PGPPublicKey encryptingKey = key.getEncryptingKey();
            if (encryptingKey == null)
                continue;
            JcePublicKeyKeyEncryptionMethodGenerator keyEncryptionMethodGenerator =
                    new JcePublicKeyKeyEncryptionMethodGenerator(encryptingKey)
                            .setProvider("BC");
            encryptedDataGenerator.addMethod(keyEncryptionMethodGenerator);
        }

        OutputStream encyptedData = encryptedDataGenerator.open(out, blackBytes.length);
        encyptedData.write(blackBytes);
        encyptedData.close();
        out.close();

        return baos.toString();
    }

    public static String sign(String redText, Key signerKey, char[] password)
            throws IOException, PGPException {
        boolean armor = true;

        byte[] redBytes = redText.getBytes("UTF-8");

        PGPSecretKey secretKey = signerKey.getSigningKey();
        PGPPublicKey publicKey = secretKey.getPublicKey();
        PGPPrivateKey privateKey = BcUtils.getPrivateKey(secretKey, password);
        if (privateKey == null)
            return redText;

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        OutputStream out = baos;
        if (armor) {
            ArmoredOutputStream aos = new ArmoredOutputStream(baos);
            aos.setHeader("Comment", Version.VERSION);
            out = aos;
        }
        BCPGOutputStream bOut = new BCPGOutputStream(out);

        PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
        OutputStream literalOutputStream = literalDataGenerator.open(bOut, PGPLiteralData.BINARY, "clip", redBytes.length, new Date());
        literalOutputStream.write(redBytes);
        literalDataGenerator.close();

        int signAlgo = publicKey.getAlgorithm();
        int hashAlgo = AlgorithmSelection.getHashAlgo(signerKey);
        MyPGP.getInstance().log2(String.format("%s: %s(%s)",
                signerKey,
                ToString.publicKey(signAlgo),
                ToString.hash(hashAlgo)));

        JcaPGPContentSignerBuilder builder =
                new JcaPGPContentSignerBuilder(signAlgo, hashAlgo)
                        .setProvider("BC");
        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(builder);
        signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);
        signatureGenerator.generateOnePassVersion(false).encode(bOut);
        signatureGenerator.update(redBytes);
        signatureGenerator.generate().encode(bOut);

        bOut.close();
        out.close();
        return baos.toString();
    }

    public static String clearsign(String redText, Key signerKey, char[] password)
            throws IOException, PGPException {
        PGPSecretKey signingKey = signerKey.getSigningKey();
        PGPPublicKey publicKey = signingKey.getPublicKey();
        PGPPrivateKey privateKey = BcUtils.getPrivateKey(signingKey, password);
        if (privateKey == null)
            return redText;

        BufferedReader reader = new BufferedReader(new StringReader(redText));
        List<String> lines = new ArrayList<String>();
        for (; ; ) {
            String line = reader.readLine();
            if (line == null)
                break;
            lines.add(line);
        }
        reader.close();

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

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
        // todo why it makes sense here and not with files?
        PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
        signatureGenerator.init(PGPSignature.CANONICAL_TEXT_DOCUMENT, privateKey);
        Iterator userIDs = publicKey.getUserIDs();
        if (userIDs.hasNext()) {
            spGen.setSignerUserID(false, (String) userIDs.next());
            signatureGenerator.setHashedSubpackets(spGen.generate());
        }

        ArmoredOutputStream aos = new ArmoredOutputStream(baos);
        aos.setHeader("Comment", Version.VERSION);
        aos.beginClearText(hashAlgo);
        int nlines = lines.size();
        for (int i = 0; i < nlines; i++) {
            String line = lines.get(i);
            line += "\r\n";
            byte[] redBytes = line.getBytes("UTF-8");
            aos.write(redBytes);
            if (i < nlines - 1)
                signatureGenerator.update(redBytes);
            else
                signatureGenerator.update(redBytes, 0, redBytes.length - 2);
        }
        aos.endClearText();

        BCPGOutputStream bOut = new BCPGOutputStream(aos);
        signatureGenerator.generate().encode(bOut);
        bOut.close();

        aos.close();
        return baos.toString("UTF-8");
    }

    public static String encrypt_sign(String redText, List<Key> publicKeys, Key signerKey, char[] password)
            throws IOException, PGPException {
        int encryptAlgo = AlgorithmSelection.getEncryptAlgo(publicKeys);
        MyPGP.getInstance().log2(Text.get("encrypt") + ": " + ToString.symmetricKey(encryptAlgo));
        int compressionAlgo = AlgorithmSelection.getCompressionAlgo(publicKeys);

        PGPSecretKey signingKey = signerKey.getSigningKey();
        PGPPublicKey publicKey = signingKey.getPublicKey();
        PGPPrivateKey pgpPrivKey = BcUtils.getPrivateKey(signingKey, password);
        if (pgpPrivKey == null)
            return redText;

        boolean armor = true;
        boolean withIntegrityCheck = true;
        byte[] redBytes = redText.getBytes("UTF-8");

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        OutputStream out = baos;
        if (armor) {
            ArmoredOutputStream aos = new ArmoredOutputStream(baos);
            aos.setHeader("Comment", Version.VERSION);
            out = aos;
        }

        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
                new JcePGPDataEncryptorBuilder(encryptAlgo)
                        .setWithIntegrityPacket(withIntegrityCheck)
                        .setSecureRandom(new SecureRandom())
                        .setProvider("BC"));
        for (Key key : publicKeys) {
            PGPPublicKey encKey = key.getEncryptingKey();
            encGen.addMethod(
                    new JcePublicKeyKeyEncryptionMethodGenerator(encKey)
                            .setProvider("BC"));
        }

        OutputStream encryptedOut = encGen.open(out, new byte[BUFFER_SIZE]);
        PGPCompressedDataGenerator compressedDataGenerator =
                new PGPCompressedDataGenerator(compressionAlgo);
        OutputStream compressedOut = compressedDataGenerator.open(encryptedOut);

        int signAlgo = publicKey.getAlgorithm();
        int hashAlgo = AlgorithmSelection.getHashAlgo(signerKey);
        MyPGP.getInstance().log2(String.format("%s: %s(%s)",
                signerKey,
                ToString.publicKey(signAlgo),
                ToString.hash(hashAlgo)));

        JcaPGPContentSignerBuilder builder =
                new JcaPGPContentSignerBuilder(signAlgo, hashAlgo)
                        .setProvider("BC");
        PGPSignatureGenerator sGen = new PGPSignatureGenerator(builder);
        sGen.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);

        Iterator it = publicKey.getUserIDs();
        if (it.hasNext()) {
            String userId = (String) it.next();
            PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
            spGen.setSignerUserID(false, userId);
            sGen.setHashedSubpackets(spGen.generate());
        }
        sGen.generateOnePassVersion(false).encode(compressedOut);

        PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
        OutputStream literalOut = literalDataGenerator.open(compressedOut,
                PGPLiteralData.BINARY, "clip", redBytes.length, new Date());
        literalOut.write(redBytes);

        sGen.update(redBytes);

        literalOut.close();
        literalDataGenerator.close();
        sGen.generate().encode(compressedOut);
        compressedOut.close();
        compressedDataGenerator.close();
        encryptedOut.close();
        encGen.close();
        out.close();

        return baos.toString();
    }

    private static String decrypt(String blackText)
            throws IOException, PasswordCancelled, PGPException {
        BcUtils.log1(String.format("%s(%s)",
                Text.get("decrypt"), Text.get("clipboard")));

        byte[] blackBytes = blackText.getBytes("UTF-8");
        InputStream is = CRLF.sanitize(new ByteArrayInputStream(blackBytes));
        PGPEncryptedDataList encryptedDataList = BcUtils.getEncryptedDataList(is, Text.get("clipboard"));
        if (encryptedDataList == null)
            return blackText;

        List<PGPPublicKeyEncryptedData> list = BcUtils.getKnownKeyEncryptedData(encryptedDataList);
        if (list.size() == 0) {
            BcUtils.log2(Text.get("no_known_key"));
            return blackText;
        }

        PGPPrivateKey sKey = null;
        PGPPublicKeyEncryptedData pbe = null;
        for (PGPPublicKeyEncryptedData item : list) {
            pbe = item;
            long id = pbe.getKeyID();
            Key key = KeyDB2.getInstance().getKey(id);
            if (key == null)
                continue;
            char[] password = GetPassword.getInstance().getDecryptionPassword(Text.get("decrypt") + ": " + key);
            if (password == null || password.length == 0)
                continue;
            PGPSecretKey pgpSecretKey = KeyDB2.getInstance().getSecretKey(id);
            sKey = BcUtils.getPrivateKey(pgpSecretKey, password);
            if (sKey != null)
                break;
        }
        if (sKey == null) {
            BcUtils.log2(Text.get("no_known_key"));
            return "";
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

        BcUtils.verifySignature(onePassSignatureList, signatureList, redBytes);

        return new String(redBytes, "UTF-8");
    }

    public static String verify(String blackText)
            throws IOException, PGPException {
        byte[] blackBytes = blackText.getBytes("UTF-8");
        InputStream is = new ByteArrayInputStream(blackBytes);
        ArmoredInputStream in = new ArmoredInputStream(is);
        List<byte[]> lines = readLines(in);

        PGPObjectFactory pgpObjectFactory = new BcPGPObjectFactory(in);
        PGPSignatureList p3 = (PGPSignatureList) pgpObjectFactory.nextObject();
        PGPSignature signature = p3.get(0);
        int signAlgo = signature.getKeyAlgorithm();
        int hashAlgo = signature.getHashAlgorithm();
        BcUtils.log2(String.format("%s: %s(%s)", Text.get("signature"), ToString.publicKey(signAlgo), ToString.hash(hashAlgo)));
        BcUtils.logSignTime(signature);

        Key key = KeyDB2.getInstance().getKey(signature.getKeyID());
        if (key == null) {
            BcUtils.log2(String.format("%s: %s", Text.get("signer"), Key.mkId8(signature.getKeyID())));
            return blackText;
        }
        BcUtils.log2(String.format("%s: %s", Text.get("signer"), key));

        PGPPublicKey publicKey = key.getPublicKey();
        signature.init(
                new JcaPGPContentVerifierBuilderProvider()
                        .setProvider("BC"),
                publicKey);

        // read the input, making sure we ignore the last newline.
        for (int i = 0; i < lines.size(); i++) {
            signature.update(lines.get(i));
            if (i < lines.size() - 1) {
                signature.update((byte) '\r');
                signature.update((byte) '\n');
            }
        }

        if (signature.verify())
            BcUtils.log2(Text.get("signature_ok"));
        else
            BcUtils.log2(Text.get("signature_bad"));

        String nl = System.getProperty("line.separator");
        StringBuilder redText = new StringBuilder();
        for (byte[] line : lines) {
            redText.append(new String(line, "UTF-8"));
            redText.append(nl);
        }
        return redText.toString();
    }

    private static List<byte[]> readLines(ArmoredInputStream in)
            throws IOException {
        List<byte[]> lines = new ArrayList<byte[]>();
        int state = 0;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (; ; ) {
            int ch = in.read();
            if (ch < 0)
                break;
            if (in.isEndOfStream() || !in.isClearText())
                break;
            if (state == 0) {
                if (ch == '\r')
                    state = 1;
                else if (ch == '\n') {
                    lines.add(baos.toByteArray());
                    baos.reset();
                } else
                    baos.write(ch);
            } else {
                if (ch == '\n') {
                    lines.add(baos.toByteArray());
                    baos.reset();
                } else {
                    baos.write('\r');
                    baos.write(ch);
                }
                state = 0;
            }
        }
        if (baos.size() > 0)
            lines.add(baos.toByteArray());
        return lines;
    }

    public static String process(String blackText)
            throws IOException, PasswordCancelled, PGPException, SignatureException {
        byte[] blackBytes = blackText.getBytes("UTF-8");

        InputStream is = CRLF.sanitize(new ByteArrayInputStream(blackBytes));
        InputStream decoderStream = PGPUtil.getDecoderStream(is);
        PGPObjectFactory pgpObjectFactory = new BcPGPObjectFactory(decoderStream);
        Object x;
        do {
            try {
                x = pgpObjectFactory.nextObject();
            } catch (Exception e) {
                return verify(blackText);
            }
            if (x == null) {
                BcUtils.log2(String.format("%s: %s", Text.get("clipboard"), Text.get("exception.bad_format")));
                return "";
            }
            if (x instanceof PGPCompressedData) {
                PGPCompressedData compressedData = (PGPCompressedData) x;
                pgpObjectFactory = new BcPGPObjectFactory(compressedData.getDataStream());
                x = pgpObjectFactory.nextObject();
            }
        } while (x instanceof PGPMarker);

        if (x instanceof PGPEncryptedDataList)
            return decrypt(blackText);

        if (x instanceof PGPSignatureList)
            return verify(blackText);

        if (x instanceof PGPOnePassSignatureList) {
            BcUtils.log1(String.format("%s(%s) :",
                    Text.get("signature"), Text.get("clipboard")));
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
            }

            PGPSignatureList signatureList = (PGPSignatureList) pgpObjectFactory.nextObject();
            BcUtils.verifySignature(onePassSignatureList, signatureList, redBytes);

            return new String(redBytes, "UTF-8");
        }

        if (x instanceof PGPPublicKey)
            BcUtils.log2(String.format("%s: %s", Text.get("clipboard"), x.getClass().getSimpleName()));
        else if (x instanceof PGPPublicKeyRing)
            BcUtils.log2(String.format("%s: %s", Text.get("clipboard"), x.getClass().getSimpleName()));
        else if (x instanceof PGPPublicKeyRingCollection)
            BcUtils.log2(String.format("%s: %s", Text.get("clipboard"), x.getClass().getSimpleName()));

        else if (x instanceof PGPSecretKey)
            BcUtils.log2(String.format("%s: %s", Text.get("clipboard"), x.getClass().getSimpleName()));
        else if (x instanceof PGPSecretKeyRing)
            BcUtils.log2(String.format("%s: %s", Text.get("clipboard"), x.getClass().getSimpleName()));
        else if (x instanceof PGPSecretKeyRingCollection)
            BcUtils.log2(String.format("%s: %s", Text.get("clipboard"), x.getClass().getSimpleName()));

        else
            BcUtils.log2(String.format("%s: %s", Text.get("clipboard"), x.getClass().getSimpleName()));

        return "";
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
}

package crypto;

import gui.AlgoPanel2;
import gui.ThreadUtilities;
import gui.Version;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Date;

/**
 * based on
 * http://bouncycastle-pgp-cookbook.blogspot.com.es/2013/01/generating-rsa-keys.html
 * <p/>
 * certainty as from
 * org.bouncycastle.jce.provider.JDKKeyPairGenerator
 */
public class KeyGenerator {

//    private static final BigInteger F4 = BigInteger.valueOf(0x10001);

    public static final int S2KCOUNT = 0xc0;

    // Note: s2kcount is a number between 0 and 0xff that controls the
    // number of times to iterate the password hash before use. More
    // iterations are useful against offline attacks, as it takes more
    // time to check each password. The actual number of iterations is
    // rather complex, and also depends on the hash function in use.
    // Refer to Section 3.7.1.3 in rfc4880.txt. Bigger numbers give
    // you more iterations.  As a rough rule of thumb, when using
    // SHA256 as the hashing function, 0x10 gives you about 64
    // iterations, 0x20 about 128, 0x30 about 256 and so on till 0xf0,
    // or about 1 million iterations.
    // The maximum you can go to is 0xff, or about 2 million iterations.
    // I'll use 0xc0 as a default -- about 130,000 iterations.

    private Date now = new Date();

    private File directory;
    private String signAlgo;
    private int signSize;
    private String encryptAlgo;
    private int encryptfrmw;
    private int encryptSize;
    private Date expireDate;
    private char[] password;
    private String userId;
    private String filename;

    public KeyGenerator(File directory,
                        String signAlgo, int signSize,
                        String encryptAlgo, int encryptSize,
                        String name, String email, String comment,
                        Date expireDate,
                        char[] password) {
        this.directory = directory;
        this.signAlgo = signAlgo;
        this.signSize = signSize;

        if (encryptAlgo == null) {
            this.encryptAlgo = null;
        } else if (encryptAlgo.equalsIgnoreCase(AlgoPanel2.RSA)) {
            this.encryptAlgo = "RSA";
        } else if (encryptAlgo.equalsIgnoreCase(AlgoPanel2.ELGAMAL)) {
            this.encryptAlgo = "ELG-E";
            this.encryptfrmw = 0;
        } else if (encryptAlgo.equalsIgnoreCase(AlgoPanel2.ELGAMAL_IETF)) {
            this.encryptAlgo = "ELG-E";
            this.encryptfrmw = 1;
        } else if (encryptAlgo.equalsIgnoreCase(AlgoPanel2.ELGAMAL_GNUPG)) {
            this.encryptAlgo = "ELG-E";
            this.encryptfrmw = 2;
        } else if (encryptAlgo.equalsIgnoreCase(AlgoPanel2.ECDH)) {
            this.encryptAlgo = "ECDH";
        }

        this.encryptSize = encryptSize;
        this.expireDate = expireDate;
        this.password = password;

        userId = String.format("%s <%s>", name, email);
        if (comment != null && comment.length() > 0)
            userId += String.format(" (%s)", comment);
        filename = email.replace('@', '_');
    }

    public String generate()
            throws IOException, PGPException,
            NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InterruptedException {
        PGPKeyPair kp_sign = null;
        if (signAlgo.equalsIgnoreCase(AlgoPanel2.RSA))
            kp_sign = mkRSASign();
        else if (signAlgo.equalsIgnoreCase(AlgoPanel2.DSA))
            kp_sign = mkDSA();
        else if (signAlgo.equalsIgnoreCase(AlgoPanel2.ECDSA))
            kp_sign = mkECDSA();

        ThreadUtilities.ifInterruptedStop();

        PGPKeyPair kp_enc = null;
        if (encryptAlgo == null)
            kp_enc = null;
        else if (encryptAlgo.equalsIgnoreCase("RSA"))
            kp_enc = mkRSAEncrypt();
        else if (encryptAlgo.equalsIgnoreCase("ELG-E")) {
            if (encryptfrmw == 0)
                kp_enc = ElgKeyGenerator.bc(encryptSize, now);
            else if (encryptfrmw == 1)
                kp_enc = ElgKeyGenerator.ietf(encryptSize, now);
            else if (encryptfrmw == 2)
                kp_enc = ElgKeyGenerator.gpg(encryptSize, now);
        } else if (encryptAlgo.equalsIgnoreCase("ECDH")) {
            kp_enc = mkECDH();
        }

        ThreadUtilities.ifInterruptedStop();

        PGPKeyRingGenerator keyRingGenerator = mkRingGenerator(kp_sign, kp_enc);
        if (keyRingGenerator == null)
            return "";

        ThreadUtilities.ifInterruptedStop();

//        File directory = Info.getHome();

        File pubFile;
        {
            PGPPublicKeyRing pkr = keyRingGenerator.generatePublicKeyRing();
            pubFile = new File(directory, filename + "_pub.asc");
            FileOutputStream fos = new FileOutputStream(pubFile);
            ArmoredOutputStream aos = new ArmoredOutputStream(fos);
            aos.setHeader("Comment", Version.VERSION);
            pkr.encode(aos);
            aos.close();
            fos.close();
        }

        {
            PGPSecretKeyRing skr = keyRingGenerator.generateSecretKeyRing();
            File secFile = new File(directory, filename + "_sec.asc");
            FileOutputStream fos = new FileOutputStream(secFile);
            ArmoredOutputStream aos = new ArmoredOutputStream(fos);
            aos.setHeader("Comment", Version.VERSION);
            skr.encode(aos);
            aos.close();
            fos.close();
        }

        return pubFile.getCanonicalPath();
    }

    private PGPKeyPair mkRSASign()
            throws NoSuchProviderException, NoSuchAlgorithmException, PGPException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(signSize);
        return new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, kpg.generateKeyPair(), now);
    }

    private PGPKeyPair mkRSAEncrypt()
            throws NoSuchProviderException, NoSuchAlgorithmException, PGPException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(encryptSize);
        return new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, kpg.generateKeyPair(), now);
    }

    private PGPKeyPair mkDSA()
            throws NoSuchProviderException, NoSuchAlgorithmException, PGPException {
        KeyPairGenerator dsaKpg = KeyPairGenerator.getInstance("DSA", "BC");
        dsaKpg.initialize(signSize);
        return new JcaPGPKeyPair(PGPPublicKey.DSA, dsaKpg.generateKeyPair(), now);
    }

    private PGPKeyPair mkECDSA()
            throws NoSuchProviderException, NoSuchAlgorithmException, PGPException, InvalidAlgorithmParameterException {
        ECParameterSpec spec = getEcCurve(signSize);
        if (spec == null)
            return null;
        KeyPairGenerator ecdsaKpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        ecdsaKpg.initialize(spec);
        return new JcaPGPKeyPair(PGPPublicKey.ECDSA, ecdsaKpg.generateKeyPair(), now);
    }

    private PGPKeyPair mkECDH()
            throws NoSuchProviderException, NoSuchAlgorithmException, PGPException, InvalidAlgorithmParameterException {
        ECParameterSpec spec = getEcCurve(encryptSize);
        if (spec == null)
            return null;
        KeyPairGenerator ecdhKpg = KeyPairGenerator.getInstance("ECDH", "BC");
        ecdhKpg.initialize(spec);
        return new JcaPGPKeyPair(PGPPublicKey.ECDH, ecdhKpg.generateKeyPair(), now);
    }

    private ECParameterSpec getEcCurve(int size) {
        if (size == AlgoPanel2.CURVE_25519)
            // wait for OpenPGP to decide parameters
            return ECNamedCurveTable.getParameterSpec("Curve-25519");
        if (size <= 192)
            return ECNamedCurveTable.getParameterSpec("P-192");
        if (size <= 224)
            return ECNamedCurveTable.getParameterSpec("P-224");
        if (size <= 256)
            return ECNamedCurveTable.getParameterSpec("P-256");     // must
        if (size <= 384)
            return ECNamedCurveTable.getParameterSpec("P-384");     // may
        if (size <= 521)
            return ECNamedCurveTable.getParameterSpec("P-521");     // should
        return null;
    }

    private PGPKeyRingGenerator mkRingGenerator(PGPKeyPair kp_sign, PGPKeyPair kp_enc)
            throws PGPException {
        // Add a self-signature on the id
        PGPSignatureSubpacketGenerator signhashgen =
                new PGPSignatureSubpacketGenerator();
        if (expireDate != null && expireDate.after(now)) {
            long seconds = (expireDate.getTime() - now.getTime()) / 1000;
            signhashgen.setKeyExpirationTime(false, seconds);
        }
        signhashgen.setKeyFlags
                (false, KeyFlags.SIGN_DATA | KeyFlags.CERTIFY_OTHER);
        signhashgen.setPreferredSymmetricAlgorithms
                (false, new int[]{
                        SymmetricKeyAlgorithmTags.AES_256,
                        SymmetricKeyAlgorithmTags.AES_192,
                        SymmetricKeyAlgorithmTags.AES_128,
                        SymmetricKeyAlgorithmTags.CAST5,
                        SymmetricKeyAlgorithmTags.TRIPLE_DES,
                });
        signhashgen.setPreferredCompressionAlgorithms
                (false, new int[]{
                        CompressionAlgorithmTags.ZLIB,
                        CompressionAlgorithmTags.BZIP2,
                        CompressionAlgorithmTags.ZIP,
                });
        signhashgen.setPreferredHashAlgorithms
                (false, new int[]{
                        HashAlgorithmTags.SHA256,
                        HashAlgorithmTags.SHA384,
                        HashAlgorithmTags.SHA512,
                        HashAlgorithmTags.SHA224,
                        HashAlgorithmTags.SHA1,
                });
        signhashgen.setFeature
                (false, Features.FEATURE_MODIFICATION_DETECTION);

        PGPDigestCalculator sha1 =
                new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1);
        PGPDigestCalculator sha256 =
                new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA256);

        PBESecretKeyEncryptor secretKeyEncryptor =
                (new BcPBESecretKeyEncryptorBuilder
                        (SymmetricKeyAlgorithmTags.AES_256, sha256, S2KCOUNT))
                        .build(password);

        BcPGPContentSignerBuilder contentSignerBuilder =
                new BcPGPContentSignerBuilder(
                        kp_sign.getPublicKey().getAlgorithm(),
                        HashAlgorithmTags.SHA256);
        PGPKeyRingGenerator keyRingGen =
                new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION,
                        kp_sign,
                        userId,
                        sha1,
                        signhashgen.generate(),
                        null,
                        contentSignerBuilder,
                        secretKeyEncryptor);

        // Add our encryption subkey, together with its signature.
        if (kp_enc != null) {
            PGPSignatureSubpacketGenerator enchashgen =
                    new PGPSignatureSubpacketGenerator();
            if (expireDate != null && expireDate.after(now)) {
                long seconds = (expireDate.getTime() - now.getTime()) / 1000;
                enchashgen.setKeyExpirationTime(false, seconds);
            }
            enchashgen.setKeyFlags(false, KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE);

            keyRingGen.addSubKey(kp_enc, enchashgen.generate(), null);
        }
        return keyRingGen;
    }
}
package bc;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;

/**
 * @author Jose A. Manas
 * @version 5.9.2014
 */
public class ToString {
    public static String publicKey(int algo) {
        switch (algo) {
            case PublicKeyAlgorithmTags.RSA_GENERAL:
                return "RSA";
            case PublicKeyAlgorithmTags.RSA_ENCRYPT:
                return "RSA";
            case PublicKeyAlgorithmTags.RSA_SIGN:
                return "RSA";
            case PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT:
                return "ELGAMAL";
            case PublicKeyAlgorithmTags.DSA:
                return "DSA";
            case PublicKeyAlgorithmTags.ECDH:
                return "EC DH";
            case PublicKeyAlgorithmTags.ECDSA:
                return "EC DSA";
            case PublicKeyAlgorithmTags.ELGAMAL_GENERAL:
                return "ELGAMAL";
            case PublicKeyAlgorithmTags.DIFFIE_HELLMAN:
                return "DIFFIE HELLMAN";
        }
        return "...?";
    }

    public static String symmetricKey(int algo) {
        switch (algo) {
            case SymmetricKeyAlgorithmTags.IDEA:
                return "IDEA (128)";
            case SymmetricKeyAlgorithmTags.TRIPLE_DES:
                return "3DES (168)";    // rfc 4880 specifies 168 derived from 192
            case SymmetricKeyAlgorithmTags.CAST5:
                return "CAST5 (128)";
            case SymmetricKeyAlgorithmTags.BLOWFISH:
                return "BLOWFISH (128)";
            case SymmetricKeyAlgorithmTags.SAFER:
                return "SAFER (128)";
            case SymmetricKeyAlgorithmTags.DES:
                return "DES (56)";
            case SymmetricKeyAlgorithmTags.AES_128:
                return "AES 128";
            case SymmetricKeyAlgorithmTags.AES_192:
                return "AES 192";
            case SymmetricKeyAlgorithmTags.AES_256:
                return "AES 256";
            case SymmetricKeyAlgorithmTags.TWOFISH:
                return "TWOFISH (256)";
            case SymmetricKeyAlgorithmTags.CAMELLIA_128:
                return "CAMELLIA 128";
            case SymmetricKeyAlgorithmTags.CAMELLIA_192:
                return "CAMELLIA 192";
            case SymmetricKeyAlgorithmTags.CAMELLIA_256:
                return "CAMELLIA 256";
        }
        return "...?";
    }

    public static String hash(int hashAlgo) {
        switch (hashAlgo) {
            case HashAlgorithmTags.MD5:
                return "MD5";
            case HashAlgorithmTags.SHA1:
                return "SHA-1";
            case HashAlgorithmTags.RIPEMD160:
                return "RIPEMD-160";
            case HashAlgorithmTags.DOUBLE_SHA:
                return "DOUBLE SHA";
            case HashAlgorithmTags.MD2:
                return "MD2";
            case HashAlgorithmTags.TIGER_192:
                return "TIGER 192";
            case HashAlgorithmTags.HAVAL_5_160:
                return "HAVAL_5 (160)";
            case HashAlgorithmTags.SHA256:
                return "SHA-256";
            case HashAlgorithmTags.SHA384:
                return "SHA-384";
            case HashAlgorithmTags.SHA512:
                return "SHA-512";
            case HashAlgorithmTags.SHA224:
                return "SHA-224";
        }
        return "...?";
    }
}

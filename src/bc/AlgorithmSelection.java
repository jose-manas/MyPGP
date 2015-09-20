package bc;

import keys.Key;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * @author Jose A. Manas
 * @version 21.8.2014
 */
public class AlgorithmSelection {
    private static int[] encryptionAlgos = {
            SymmetricKeyAlgorithmTags.AES_256,
            SymmetricKeyAlgorithmTags.AES_192,
            SymmetricKeyAlgorithmTags.AES_128,
            SymmetricKeyAlgorithmTags.CAST5,
            SymmetricKeyAlgorithmTags.TWOFISH,
            SymmetricKeyAlgorithmTags.TRIPLE_DES,
    };

    private static int[] hashAlgos = {
            HashAlgorithmTags.SHA256,
            HashAlgorithmTags.SHA384,
            HashAlgorithmTags.SHA512,
            HashAlgorithmTags.SHA224,
            HashAlgorithmTags.RIPEMD160,
            HashAlgorithmTags.SHA1,
    };

    private static final int[] MASTER_KEY_CERTIFICATION_TYPES = new int[]{
            PGPSignature.POSITIVE_CERTIFICATION,
            PGPSignature.CASUAL_CERTIFICATION,
            PGPSignature.NO_CERTIFICATION,
            PGPSignature.DEFAULT_CERTIFICATION
    };

    public static int getEncryptAlgo(List<Key> publicKeys) {
        List<Integer> preferences = null;
        for (Key key : publicKeys) {
            PGPPublicKey publicKey = key.getPublicKey();
            int[] algos = getPreferredEncryptionAlgos(publicKey);
            if (algos == null || algos.length == 0)
                continue;
            preferences = filter(preferences, algos);
        }

        if (preferences != null && preferences.size() > 0) {
            for (int algo : encryptionAlgos) {
                if (preferences.contains(algo))
                    return algo;
            }
        }
        // // RFC 2440 5.2.3.8 & 9.2
        return SymmetricKeyAlgorithmTags.TRIPLE_DES;
    }

    public static int[] getPreferredEncryptionAlgos(PGPPublicKey key) {
        List<PGPSignatureSubpacketVector> svList = getSignatureSubpacketVectors(key);
        for (PGPSignatureSubpacketVector sv : svList) {
            int[] algos = sv.getPreferredSymmetricAlgorithms();
            if (algos != null && algos.length > 0)
                return algos;
        }
        return null;
    }

    public static int getHashAlgo(List<Key> signingKeys) {
        List<Integer> preferences = null;
        for (Key key : signingKeys) {
            PGPPublicKey publicKey = key.getPublicKey();
            int[] algos = getPreferredEncryptionAlgos(publicKey);
            if (algos == null || algos.length == 0)
                continue;
            preferences = filter(preferences, algos);
        }

        if (preferences != null && preferences.size() > 0) {
            for (int algo : hashAlgos) {
                if (preferences.contains(algo))
                    return algo;
            }
        }
        // RFC 2440 5.2.3.8 & 9.2
        return HashAlgorithmTags.SHA1;
    }

    public static int getHashAlgo(Key signingKey) {
        List<Integer> preferences = null;
        PGPPublicKey publicKey = signingKey.getPublicKey();
        int[] algos = getPreferredHashAlgos(publicKey);
        if (algos != null && algos.length != 0) {
            List<Integer> result = new ArrayList<Integer>();
            for (int algo : algos)
                result.add(algo);
            preferences = result;
        }

        if (preferences != null && preferences.size() > 0) {
            for (int algo : hashAlgos) {
                if (preferences.contains(algo))
                    return algo;
            }
        }
        // RFC 2440 5.2.3.7 & 9.4
        return HashAlgorithmTags.SHA1;
    }

    private static int[] getPreferredHashAlgos(PGPPublicKey key) {
        List<PGPSignatureSubpacketVector> svList = getSignatureSubpacketVectors(key);
        for (PGPSignatureSubpacketVector sv : svList) {
            int[] algos = sv.getPreferredHashAlgorithms();
            if (algos != null && algos.length > 0)
                return algos;
        }
        return null;
    }

    public static int getCompressionAlgo(List<Key> publicKeys) {
        List<Integer> preferences = null;
        for (Key key : publicKeys) {
            PGPPublicKey publicKey = key.getPublicKey();
            int[] algos = getPreferredCompressionAlgos(publicKey);
            if (algos == null || algos.length == 0)
                continue;
            preferences = filter(preferences, algos);
        }

        try {
            return preferences.get(0);
        } catch (Exception e) {
            // RFC 2440 5.2.3.8 & 9.3
            return CompressionAlgorithmTags.ZIP;
        }
    }

    private static int[] getPreferredCompressionAlgos(PGPPublicKey key) {
        List<PGPSignatureSubpacketVector> svList = getSignatureSubpacketVectors(key);
        for (PGPSignatureSubpacketVector sv : svList) {
            int[] algos = sv.getPreferredCompressionAlgorithms();
            if (algos != null && algos.length > 0)
                return algos;
        }
        return null;
    }

    private static List<PGPSignatureSubpacketVector> getSignatureSubpacketVectors(PGPPublicKey key) {
        List<PGPSignatureSubpacketVector> result = new ArrayList<PGPSignatureSubpacketVector>();
        if (key.isMasterKey()) {
            for (int certificationType : MASTER_KEY_CERTIFICATION_TYPES) {
                Iterator eIt = key.getSignaturesOfType(certificationType);
                while (eIt.hasNext()) {
                    PGPSignature signature = (PGPSignature) eIt.next();
                    if (signature.hasSubpackets())
                        result.add(signature.getHashedSubPackets());
                }
            }
        } else {
            Iterator eIt = key.getSignaturesOfType(PGPSignature.SUBKEY_BINDING);
            while (eIt.hasNext()) {
                PGPSignature signature = (PGPSignature) eIt.next();
                if (signature.hasSubpackets())
                    result.add(signature.getHashedSubPackets());
            }
        }
        return result;
    }

    private static List<Integer> filter(List<Integer> preferences, int[] algos) {
        List<Integer> result = new ArrayList<Integer>();
        if (preferences == null) {
            for (int algo : algos)
                result.add(algo);
        } else {
            for (int algo : preferences) {
                if (contains(algo, algos))
                    result.add(algo);
            }
        }
        return result;
    }

    private static boolean contains(int algo, int[] algos) {
        for (int x : algos) {
            if (x == algo)
                return true;
        }
        return false;
    }
}

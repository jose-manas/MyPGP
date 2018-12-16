package keys;

import gui.MyPGP;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;

import java.io.PrintWriter;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Map;
import java.util.Set;

// 22.5.2011 alias
// 24.6.2011 signatures
// 19.7.2011 subkeys for encryption: ssb
// 26.6.2013 only 1: static
// 24.8.2017 remove singleton architecture

/**
 * @author Jose A. Manas
 * @version 7.7.2012
 */
public class KeyDB2 {
    private static Map<Long, Key> keys = new Hashtable<>();
    private static Map<Long, PGPPublicKey> publicKeys = new Hashtable<>();
    private static Map<Long, PGPSecretKey> secretKeys = new Hashtable<>();

    public static Key getKey(long id) {
        return keys.get(id);
    }

    static Key getKey(String kid) {
        kid = kid.toLowerCase();
        for (Key key : keys.values()) {
            String kid1 = key.getKid().toLowerCase();
            if (kid1.endsWith(kid))
                return key;
        }
        return null;
    }

//    public static Set<Key> getSecretKeys() {
//        Set<Key> keySet = new TreeSet<>(new Comparator<Key>() {
//            Collator collator = Collator.getInstance(Text.getLocale());
//
//            public int compare(Key key1, Key key2) {
//                return collator.compare(key1.toString(), key2.toString());
//            }
//        });
//        for (Key key : keys.values()) {
//            if (key.isSecret())
//                keySet.add(key);
//        }
//        return keySet;
//    }

    public static PGPPublicKey getPublicKey(Long id) {
        return publicKeys.get(id);
    }

    public static PGPSecretKey getSecretKey(Long id) {
        return secretKeys.get(id);
    }

    public static void setAlias(long kid, String alias) {
        Key key = keys.get(kid);
        if (key != null)
            key.setAlias(alias);
    }

    public static void setAlias(String kid, String alias) {
        kid = kid.toLowerCase();
        for (Key key : keys.values()) {
            String kid1 = key.getKid().toLowerCase();
            if (kid1.endsWith(kid)) {
                key.setAlias(alias);
                return;
            }
        }
    }

    static void saveKeys(PrintWriter writer) {
        Set<Key> unique = new HashSet<>();
        unique.addAll(keys.values());
        for (Key key : unique) {
            if (key.hasAlias())
                writer.printf("alias.%s= %s%n", key.getKid(), key.getAlias());
        }
    }

    static Key store(PGPPublicKey masterKey, PGPPublicKey publicKey) {
        publicKeys.put(publicKey.getKeyID(), publicKey);
        if (masterKey == null) {
            MyPGP.log("no master key for " + publicKey);
            return null;
        }

//        long id = pgpPublicKey.getKeyID();
        long masterId = masterKey.getKeyID();
        Key key = keys.get(masterId);
        if (key == null) {
            key = new Key(masterKey);
            keys.put(masterId, key);
        }
        keys.put(publicKey.getKeyID(), key);
        key.add(publicKey);
        return key;
    }

    static Key store(PGPSecretKey masterKey, PGPSecretKey secretKey) {
        secretKeys.put(secretKey.getKeyID(), secretKey);
        if (masterKey == null) {
            MyPGP.log("no master key for " + secretKey);
            return null;
        }

//        long id = pgpSecretKey.getKeyID();
        long masterId = masterKey.getKeyID();
        Key key = keys.get(masterId);
        if (key == null) {
            key = new Key(masterKey);
            keys.put(masterId, key);
        }
        keys.put(secretKey.getKeyID(), key);
        key.add(secretKey);
        return key;
    }

    public static void reset() {
        keys.clear();
        publicKeys.clear();
        secretKeys.clear();
    }

    public static void trace(long id) {
        Key key = keys.get(id);
        if (key != null)
            key.show();
    }
}

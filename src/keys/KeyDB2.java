package keys;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;

import java.io.PrintWriter;
import java.util.*;

// 22.5.2011 alias
// 24.6.2011 signatures
// 19.7.2011 subkeys for encryption: ssb
// 26.6.2013 only 1: static

/**
 * @author Jose A. Manas
 * @version 7.7.2012
 */
public class KeyDB2 {
    private static KeyDB2 instance = new KeyDB2();

    public static KeyDB2 getInstance() {
        return instance;
    }

    private Map<Long, Key> keys = new Hashtable<Long, Key>();
    private Map<Long, PGPPublicKey> publicKeys = new Hashtable<Long, PGPPublicKey>();
    private Map<Long, PGPSecretKey> secretKeys = new Hashtable<Long, PGPSecretKey>();

    public Key getKey(long id) {
        return keys.get(id);
    }

    public Key getKey(String kid) {
        kid = kid.toLowerCase();
        for (Key key : keys.values()) {
            String kid1 = key.getKid().toLowerCase();
            if (kid1.endsWith(kid))
                return key;
        }
        return null;
    }

    public Set<Key> getSecretKeys() {
        Set<Key> keySet = new TreeSet<Key>(Key.KEY_COMPARATOR);
        for (Key key : keys.values()) {
            if (key.isSecret())
                keySet.add(key);
        }
        return keySet;
    }

    public PGPPublicKey getPublicKey(Long id) {
        return publicKeys.get(id);
    }

    public PGPSecretKey getSecretKey(Long id) {
        return secretKeys.get(id);
    }

    public void setAlias(long kid, String alias) {
        Key key = keys.get(kid);
        if (key != null)
            key.setAlias(alias);
    }

    public void setAlias(String kid, String alias) {
        kid = kid.toLowerCase();
        for (Key key : keys.values()) {
            String kid1 = key.getKid().toLowerCase();
            if (kid1.endsWith(kid)) {
                key.setAlias(alias);
                return;
            }
        }
    }

    void saveKeys(PrintWriter writer) {
        Set<Key> unique = new HashSet<Key>();
        unique.addAll(keys.values());
        for (Key key : unique) {
            if (key.hasAlias())
                writer.printf("alias.%s= %s%n", key.getKid(), key.getAlias());
        }
    }

    public Key store(PGPPublicKey masterKey, PGPPublicKey publicKey) {
        publicKeys.put(publicKey.getKeyID(), publicKey);
        if (masterKey == null) {
            System.out.println("no master key for " + publicKey);
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

    public Key store(PGPSecretKey masterKey, PGPSecretKey secretKey) {
        secretKeys.put(secretKey.getKeyID(), secretKey);
        if (masterKey == null) {
            System.out.println("no master key for " + secretKey);
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

    public void reset() {
        keys.clear();
    }

    public void trace(long id) {
        Key key = keys.get(id);
        if (key != null)
            key.show();
    }
}

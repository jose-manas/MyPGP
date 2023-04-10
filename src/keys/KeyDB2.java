package keys;

import gui.LogWindow;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;

import java.io.PrintWriter;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Map;
import java.util.Set;

/**
 * Key store.
 * indexed by masterkey.id
 * @author Jose A. Manas
 * @version 7.7.2012
 */
public class KeyDB2 {
    private static boolean TRACE= false;

    private static final Map<Long, Key> keyList = new Hashtable<>();
    private static final Map<Long, PGPPublicKey> publicKeys = new Hashtable<>();
    private static final Map<Long, PGPSecretKey> secretKeys = new Hashtable<>();

    public static Key getKey(long id) {
        return keyList.get(id);
    }

    static Key getKey(String kid) {
        kid = kid.toLowerCase();
        for (Key key : keyList.values()) {
            String kid1 = key.getKid().toLowerCase();
            if (kid1.endsWith(kid))
                return key;
        }
        return null;
    }

    public static PGPPublicKey getPublicKey(Long id) {
        return publicKeys.get(id);
    }

    public static PGPSecretKey getSecretKey(Long id) {
        return secretKeys.get(id);
    }

    public static void setAlias(long kid, String alias) {
        Key key = keyList.get(kid);
        if (key != null)
            key.setAlias(alias);
    }

    public static void setAlias(String kid, String alias) {
        kid = kid.toLowerCase();
        for (Key key : keyList.values()) {
            String kid1 = key.getKid().toLowerCase();
            if (kid1.endsWith(kid)) {
                key.setAlias(alias);
                return;
            }
        }
    }

    static void saveKeys(PrintWriter writer) {
        Set<Key> unique = new HashSet<>(keyList.values());
        for (Key key : unique) {
            if (key.hasAlias())
                writer.printf("alias.%s= %s%n", key.getKid(), key.getAlias());
        }
    }

    static Key store(PGPPublicKey masterKey, PGPPublicKey publicKey) {
        if (TRACE) {
            System.out.println("KeyDB2.store()");
            System.out.printf("  masterKey: %x%n", masterKey.getKeyID());
            System.out.printf("  publicKey: %x%n", publicKey.getKeyID());
        }
        publicKeys.put(publicKey.getKeyID(), publicKey);
        if (masterKey == null) {
//            MyPGP.log("no master key for " + publicKey);
            LogWindow.add("no master key for " + publicKey);
            return null;
        }

        long masterId = masterKey.getKeyID();
        Key key = keyList.get(masterId);
        if (key == null) {
            key = new Key(masterKey);
            keyList.put(masterId, key);
        }
        keyList.put(publicKey.getKeyID(), key);
        key.add(publicKey);
        if (TRACE) {
            System.out.println("KeyDB2.publicKeys");
            for (Long id: publicKeys.keySet()) {
                PGPPublicKey k = publicKeys.get(id);
                System.out.printf("  %x -> %x%n", id, k.getKeyID());
            }
            System.out.println("KeyDB2.secretKeys");
            for (Long id: secretKeys.keySet()) {
                PGPSecretKey k = secretKeys.get(id);
                System.out.printf("  %x -> %x%n", id, k.getKeyID());
            }
            System.out.println();
        }
        return key;
    }

    static Key store(PGPPublicKey masterKey, PGPSecretKey secretKey) {
        if (TRACE) {
            System.out.println("KeyDB2.store()");
            System.out.printf("  masterKey: %x%n", masterKey.getKeyID());
            System.out.printf("  secretKey: %x%n", secretKey.getKeyID());
        }
        secretKeys.put(secretKey.getKeyID(), secretKey);
        PGPPublicKey pgppk = secretKey.getPublicKey();
        if (pgppk != null)
            publicKeys.put(pgppk.getKeyID(), pgppk);
        if (masterKey == null) {
//            MyPGP.log("no master key for " + secretKey);
            LogWindow.add("no master key for " + secretKey);
            return null;
        }

        long masterId = masterKey.getKeyID();
        Key key = keyList.get(masterId);
        if (key == null) {
            key = new Key(masterKey);
            keyList.put(masterId, key);
        }
        keyList.put(secretKey.getKeyID(), key);
        key.add(secretKey);

        if (TRACE) {
            System.out.println("KeyDB2.publicKeys");
            for (Long id: publicKeys.keySet()) {
                PGPPublicKey k = publicKeys.get(id);
                System.out.printf("  %x -> %x%n", id, k.getKeyID());
            }
            System.out.println("KeyDB2.secretKeys");
            for (Long id: secretKeys.keySet()) {
                PGPSecretKey k = secretKeys.get(id);
                System.out.printf("  %x -> %x%n", id, k.getKeyID());
            }
        }
        return key;
    }

    public static void reset() {
        keyList.clear();
        publicKeys.clear();
        secretKeys.clear();
    }

    public static void trace(long id) {
        Key key = keyList.get(id);
        if (key != null)
            key.show();
    }
}

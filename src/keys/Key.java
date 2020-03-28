package keys;

// 22.5.2011 alias
// 24.6.2011 signatures
// 1.12.2011 take into account that two keys may have the same name: compare kid's

import gui.Text;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.util.encoders.Hex;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * @author Jose A. Manas
 * @version 27.4.2011
 */
public class Key
        implements Comparable {
    private static final int[] MASTER_KEY_CERTIFICATION_TYPES = new int[]{
            PGPSignature.POSITIVE_CERTIFICATION,
            PGPSignature.CASUAL_CERTIFICATION,
            PGPSignature.NO_CERTIFICATION,
            PGPSignature.DEFAULT_CERTIFICATION
    };

    private PGPPublicKey publicKey;
    private PGPSecretKey secretKey;

    private String kid;
    private String kid8;
    private String kcreation;
    private String kexp;
    private String name;
    private List<String> moreNames;
    private String alias;
    private String fingerprint;
    private Set<File> fileList = new HashSet<>();

    private String corePresentation;
    private Map<Long, PGPPublicKey> publicSubkeys = new HashMap<>();
    private Map<Long, PGPSecretKey> secretSubkeys = new HashMap<>();
    private final Set<Long> signerIds = new HashSet<>();

    public Key(PGPPublicKey publicKey) {
        setPublicKey(publicKey);
    }

    public Key(PGPSecretKey secretKey) {
        setSecretKey(secretKey);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Key key = (Key) o;

        return kid != null ? kid.equals(key.kid) : key.kid == null;
    }

    @Override
    public int hashCode() {
        return kid != null ? kid.hashCode() : 0;
    }

    private void loadNames(Iterator it) {
        while (it.hasNext()) {
            String id = (String) it.next();
            if (name == null) {
                name = id;
            } else {
                if (moreNames == null)
                    moreNames = new ArrayList<>();
                moreNames.add(id);
            }
        }
    }

    private void saveSigners(Iterator signatures) {
        while (signatures.hasNext()) {
            PGPSignature signature = (PGPSignature) signatures.next();
            long sid = signature.getKeyID();
            signerIds.add(sid);
        }
    }

    /**
     * Signers (certifiers) of a key.
     * No duplicate.
     *
     * @return list of signers different from its owner.
     */
    public List<Long> getSigIds() {
        List<Long> shortList = new ArrayList<>();
        for (Long sid : signerIds) {
            if (shortList.contains(sid))
                continue;
            if (getId() == sid)
                continue;
            if (publicSubkeys.containsKey(sid))
                continue;
            if (secretSubkeys.containsKey(sid))
                continue;
            shortList.add(sid);
        }
        return shortList;
    }

    public String toString() {
        if (alias != null && alias.length() > 0)
            return alias;
        else if (name != null && name.length() > 0)
            return name;
        else
            return kid;
    }

    public int compareTo(Object o) {
        if (this == o)
            return 0;
        Key she = (Key) o;
        String myText = name;
        if (hasAlias())
            myText = alias;
        if (myText == null)
            return -1;
        String herText = she.name;
        if (she.hasAlias())
            herText = she.alias;
        if (herText == null)
            return 1;
        int cmp = myText.compareToIgnoreCase(herText);
        if (cmp == 0)
            cmp = kid.compareToIgnoreCase(she.kid);
        return cmp;
    }

    public String getKid() {
        return kid;
    }

    public String getKid8() {
        return kid8;
    }

    public String getAlias() {
        return alias;
    }

    void setAlias(String alias) {
        if (alias == null || alias.length() == 0 ||
                alias.equals(getCorePresentation()))
            this.alias = null;
        else
            this.alias = alias;
    }

    boolean hasAlias() {
        return alias != null && alias.length() > 0;
    }

    public Object getCorePresentation() {
        if (corePresentation == null) {
            StringBuilder builder = new StringBuilder();
            if (kcreation != null) {
                if (kexp == null)
                    builder.append(String.format("[%s]", kcreation));
                else
                    builder.append(String.format("[%s, %s]", kcreation, kexp));
            }
            if (name != null)
                builder.append(' ').append(name);
            corePresentation = builder.toString();
        }
        return corePresentation;
    }

    public String getFingerprintHex4() {
        StringBuilder builder = new StringBuilder();
        int blocks = (fingerprint.length() + 3) / 4;
        for (int b = 0; b < blocks - 1; b++)
            builder.append(fingerprint, b * 4, (b + 1) * 4).append(" ");
        builder.append(fingerprint.substring((blocks - 1) * 4));
        return builder.toString();
    }

    public String getIdFingerprint() {
        StringBuilder builder = new StringBuilder();
        builder.append('[').append(kid8).append(']');
        if (fingerprint != null && fingerprint.length() > 0) {
            builder.append(" ");
            builder.append(Text.get("fingerprint")).append(": ").append(getFingerprintHex4());
        }
        return builder.toString();
    }

    public boolean isSecret() {
        return secretKey != null;
    }

    @SuppressWarnings("SimplifiableIfStatement")
    public boolean isMasterKey() {
        if (publicKey != null)
            return publicKey.isMasterKey();
        if (secretKey != null)
            return secretKey.isMasterKey();
        return false;
    }

    public long getId() {
        if (publicKey != null)
            return publicKey.getKeyID();
        if (secretKey != null)
            return secretKey.getKeyID();
        return 0L;
    }

    public PGPPublicKey getPublicKey() {
        if (publicKey != null)
            return publicKey;
        if (secretKey != null)
            return secretKey.getPublicKey();
        return null;
    }

    public void setPublicKey(PGPPublicKey publicKey) {
        saveSigners(publicKey.getSignatures());
        if (this.publicKey != null)
            return;
        this.publicKey = publicKey;

        loadNames(publicKey.getUserIDs());
        kid = String.format("%016X", publicKey.getKeyID());
        kid8 = kid.substring((kid.length() - 8));
//        System.out.println("public: [" + kid8 + "] " + name);
        Date creationDate = publicKey.getCreationTime();
        SimpleDateFormat sdf = new SimpleDateFormat("d.M.yyyy");
        kcreation = sdf.format(creationDate);
        long validSeconds = publicKey.getValidSeconds();
        if (validSeconds > 0) {
            Calendar calendar = Calendar.getInstance();
            calendar.setTime(creationDate);
            calendar.add(Calendar.SECOND, (int) validSeconds);
            kexp = sdf.format(calendar.getTime());
        }
        fingerprint = Hex.toHexString(publicKey.getFingerprint());
    }

    private void setSecretKey(PGPSecretKey secretKey) {
        saveSigners(secretKey.getPublicKey().getSignatures());
        if (this.secretKey != null)
            return;
        this.secretKey = secretKey;
        setPublicKey(secretKey.getPublicKey());
    }

    public void add(PGPPublicKey publicKey) {
        if (publicKey.isMasterKey())
            setPublicKey(publicKey);
        else
            publicSubkeys.put(publicKey.getKeyID(), publicKey);
    }

    public void add(PGPSecretKey secretKey) {
        if (secretKey.isMasterKey())
            setSecretKey(secretKey);
        else
            secretSubkeys.put(secretKey.getKeyID(), secretKey);
    }

    public PGPPublicKey getEncryptingKey() {
        for (PGPPublicKey psk : publicSubkeys.values()) {
            if (isValidForEncrypting(psk))
                return psk;
        }
        if (isValidForEncrypting(publicKey))
            return publicKey;
        return null;
    }

    @SuppressWarnings("RedundantIfStatement")
    private boolean isValidForEncrypting(PGPPublicKey key) {
        if (!key.isEncryptionKey())
            return false;
        if (key.hasRevocation())
            return false;
        if (!hasKeyFlags(key, KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE))
            return false;
        return true;
    }

    public PGPSecretKey getSigningKey() {
        if (secretKey != null && isValidForSigning(secretKey))
            return secretKey;
        return null;
    }

    @SuppressWarnings("RedundantIfStatement")
    private boolean isValidForSigning(PGPSecretKey key) {
        if (key == null)
            throw new IllegalArgumentException("key == null");
        if (!key.isSigningKey())
            return false;
        if (!hasKeyFlags(secretKey.getPublicKey(), KeyFlags.SIGN_DATA))
            return false;
        return true;
    }

    private static boolean hasKeyFlags(PGPPublicKey key, int keyUsage) {
        if (key.isMasterKey()) {
            for (int certificationType : MASTER_KEY_CERTIFICATION_TYPES) {
                Iterator eIt = key.getSignaturesOfType(certificationType);
                while (eIt.hasNext()) {
                    PGPSignature signature = (PGPSignature) eIt.next();
                    if (!isMatchingUsage(signature, keyUsage))
                        return false;
                }
            }
        } else {
            Iterator eIt = key.getSignaturesOfType(PGPSignature.SUBKEY_BINDING);
            while (eIt.hasNext()) {
                PGPSignature signature = (PGPSignature) eIt.next();
                if (!isMatchingUsage(signature, keyUsage))
                    return false;
            }
        }
        return true;
    }

    private static boolean isMatchingUsage(PGPSignature signature, int keyUsage) {
        if (signature.hasSubpackets()) {
            PGPSignatureSubpacketVector sv = signature.getHashedSubPackets();
            int flags = sv.getKeyFlags();
            if (flags == 0)
                return true;        // no usage restriction
            if ((flags & keyUsage) == 0)
                return false;
        }
        return true;
    }

    public void show() {
        if (publicKey != null || publicSubkeys.size() > 0) {
            System.out.print("  PUBLIC:");
            if (publicKey != null)
                System.out.print(" " + mkId8(publicKey.getKeyID()));
            System.out.print(" [");
            for (Long id : publicSubkeys.keySet())
                System.out.print(" " + mkId8(id));
            System.out.print(" ]");
            System.out.println();
        }
        if (secretKey != null || secretSubkeys.size() > 0) {
            System.out.print("  PRIVATE:");
            if (secretKey != null)
                System.out.print(" " + mkId8(secretKey.getKeyID()));
            System.out.print(" [");
            for (Long id : secretSubkeys.keySet())
                System.out.print(" " + mkId8(id));
            System.out.print(" ]");
            System.out.println();
        }
    }

    public static String mkId8(Long id) {
        String s16 = String.format("%016X", id);
        return s16.substring(s16.length() - 8);
    }

    public void trace() {
        System.out.print("    " + getKid8());
        if (publicKey != null) {
            if (publicKey.isMasterKey())
                System.out.print(" master");
            if (publicKey.isEncryptionKey())
                System.out.print(" encryption");
            if (publicKey.hasRevocation())
                System.out.print(" revoked");
        }
        if (secretKey != null) {
            if (secretKey.isMasterKey())
                System.out.print(" master");
            if (secretKey.isPrivateKeyEmpty())
                System.out.print(" privateKeyEmpty");
            if (secretKey.isSigningKey())
                System.out.print(" signing");
        }
        System.out.println();
    }

    public String getEmail() {
        try {
            int start = name.indexOf('<');
            int end = name.indexOf('>', start);
            return name.substring(start + 1, end);
        } catch (Exception e) {
            return name;
        }
    }

    public List<PGPPublicKey> getPublicKeyList() {
        List<PGPPublicKey> list = new ArrayList<>();
        list.add(publicKey);
        list.addAll(publicSubkeys.values());
        return list;
    }

    public List<PGPSecretKey> getSecretKeyList() {
        List<PGPSecretKey> list = new ArrayList<>();
        if (secretKey != null)
            list.add(secretKey);
        list.addAll(secretSubkeys.values());
        return list;
    }

    public Set<File> getFileList() {
        return fileList;
    }

    public void setFile(File file) {
        fileList.add(file);
    }

    public String getKcreation() {
        return kcreation;
    }

    public String getKexp() {
        return kexp;
    }
}

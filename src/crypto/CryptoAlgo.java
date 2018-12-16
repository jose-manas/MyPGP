package crypto;

/**
 * @author Jose A. Manas
 * @version 23.9.2017
 */
public class CryptoAlgo {
    public static final String RSA_1024 = "RSA: 1024 bits";
    public static final String RSA_2048 = "RSA: 2048 bits";
    public static final String RSA_3072 = "RSA: 3072 bits";
    public static final String RSA_4096 = "RSA: 4096 bits";

    public static final String DSA_1024 = "DSA: 1024 bits";
    public static final String DSA_2048 = "DSA: 2048 bits";
    public static final String DSA_3072 = "DSA: 3072 bits";
//    public static final String DSA_4096 = "DSA: 4096 bits";

    public static final String ECDSA_192 = "ECDSA: P-192 (192 bits)";
    public static final String ECDSA_224 = "ECDSA: P-224 (224 bits)";
    public static final String ECDSA_256 = "ECDSA: P-256 (256 bits)";
    public static final String ECDSA_384 = "ECDSA: P-384 (384 bits)";
    public static final String ECDSA_521 = "ECDSA: P-521 (521 bits)";
    public static final String ECDSA_25519 = "ECDSA: 25519 (256 bits)";

    public static final String IETF_1024 = "Elgamal: IETF 1024 bits";
    public static final String IETF_1536 = "Elgamal: IETF 1536 bits";
    public static final String IETF_2048 = "Elgamal: IETF 2048 bits";
    public static final String IETF_3072 = "Elgamal: IETF 3072 bits";
    public static final String IETF_4096 = "Elgamal: IETF 4096 bits";

    public static final String GPG_1024 = "Elgamal: GnuPG 1024 bits";
    public static final String GPG_1536 = "Elgamal: GnuPG 1536 bits";
    public static final String GPG_2048 = "Elgamal: GnuPG 2048 bits";
    public static final String GPG_3072 = "Elgamal: GnuPG 3072 bits";
    public static final String GPG_4096 = "Elgamal: GnuPG 4096 bits";

    public static final String ELG_1024 = "Elgamal: 1024 bits";
    public static final String ELG_1536 = "Elgamal: 1536 bits";
    public static final String ELG_2048 = "Elgamal: 2048 bits";
    public static final String ELG_3072 = "Elgamal: 3072 bits";
    public static final String ELG_4096 = "Elgamal: 4096 bits";

    public static final String ECDH_192 = "ECDH: P-192 (192 bits)";
    public static final String ECDH_224 = "ECDH: P-224 (224 bits)";
    public static final String ECDH_256 = "ECDH: P-256 (256 bits)";
    public static final String ECDH_384 = "ECDH: P-384 (384 bits)";
    public static final String ECDH_521 = "ECDH: P-521 (521 bits)";
    public static final String ECDH_25519 = "ECDH: 25519 (256 bits)";

    private final String code;
    private String shortText;

    public CryptoAlgo(String code) {
        this.code = code;
        try {
            int dotdot = code.indexOf(':');
            shortText = code.substring(dotdot + 1).trim();
        } catch (Exception e) {
            shortText = code;
        }
    }

    public String getCode() {
        return code;
    }

    @Override
    public String toString() {
        return shortText;
    }
}

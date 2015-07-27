package crypto;

import org.bouncycastle.jce.spec.ElGamalParameterSpec;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Date;

/**
 * @author Jose A. Manas
 * @version 17.8.2014
 */
public class ElgKeyGenerator {
    public static PGPKeyPair bc(int encryptSize, Date now)
            throws PGPException,
            NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InterruptedException {
        BigInteger[] pg = StdElgamal.generateParameters(encryptSize);
        BigInteger p = pg[0];
        BigInteger g = pg[1];
        KeyPairGenerator elgKpg = KeyPairGenerator.getInstance("ELGAMAL", "BC");
        ElGamalParameterSpec elgParams = new ElGamalParameterSpec(p, g);
        elgKpg.initialize(elgParams);
        return new JcaPGPKeyPair(PGPPublicKey.ELGAMAL_ENCRYPT, elgKpg.generateKeyPair(), now);
    }

    public static PGPKeyPair ietf(int encryptSize, Date now)
            throws PGPException,
            NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        BigInteger[] pg = IETF.get(encryptSize);
        if (pg == null)
            return null;
        BigInteger p = pg[0];
        BigInteger g = pg[1];
        KeyPairGenerator elgKpg = KeyPairGenerator.getInstance("ELGAMAL", "BC");
        ElGamalParameterSpec elgParams = new ElGamalParameterSpec(p, g);
        elgKpg.initialize(elgParams);
        return new JcaPGPKeyPair(PGPPublicKey.ELGAMAL_ENCRYPT, elgKpg.generateKeyPair(), now);
    }

    public static PGPKeyPair gpg(int encryptSize, Date now)
            throws PGPException,
            NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InterruptedException {
        BigInteger[] pg = GpgElgamal.generateParameters(encryptSize);
        BigInteger p = pg[0];
        BigInteger g = pg[1];
        KeyPairGenerator elgKpg = KeyPairGenerator.getInstance("ELGAMAL", "BC");
        ElGamalParameterSpec elgParams = new ElGamalParameterSpec(p, g);
        elgKpg.initialize(elgParams);
        return new JcaPGPKeyPair(PGPPublicKey.ELGAMAL_ENCRYPT, elgKpg.generateKeyPair(), now);
    }
}

package crypto;

import bc.Provider;
import gui.ThreadUtilities;
import org.bouncycastle.util.BigIntegers;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Standard implementation of parameters for Elgamal encryption.
 *
 * @author Jose A. Manas
 * @version 17.8.2014
 */
public class StdElgamal {
    private static final SecureRandom random = new SecureRandom();

    /**
     * Finds a pair of prime BigInteger's {p, q: p = 2q + 1}
     * <p/>
     * (see: Handbook of Applied Cryptography 4.86)
     */
    public static BigInteger[] generateParameters(int size)
            throws InterruptedException {
//        System.out.println("  generateP(): " + new Date());
        BigInteger p = generateP(size);

        ThreadUtilities.ifInterruptedStop();

//        System.out.println("  selectGenerator():    " + new Date());
        BigInteger g = selectGenerator(p);
//        System.out.println("  done:                 " + new Date());
//        System.out.println();
        return new BigInteger[]{p, g};
    }

    /**
     * // crypto/generators/DHParametersHelper.java
     * Finds a safe prime p.
     * Finds a pair of prime BigInteger's {p, q: p = 2q + 1}
     * <p/>
     * (see: Handbook of Applied Cryptography 4.86)
     */
    private static BigInteger generateP(int nbits)
            throws InterruptedException {
        int certainty = 20;
        int qLength = nbits - 1;

        for (; ; ) {
            BigInteger q = new BigInteger(qLength, 2, random);
            // p <- 2q + 1
            BigInteger p = q.shiftLeft(1).add(BigInteger.ONE);
            if (p.isProbablePrime(certainty) && (certainty <= 2 || q.isProbablePrime(certainty)))
                return p;

            ThreadUtilities.ifInterruptedStop();
        }
    }

    /**
     * crypto/generators/DHParametersHelper.java
     */
    private static BigInteger selectGenerator(BigInteger p)
            throws InterruptedException {
        BigInteger TWO = BigInteger.valueOf(2);
        BigInteger pMinusTwo = p.subtract(TWO);
        BigInteger g;

        /*
         * RFC 2631 2.2.1.2 (and see: Handbook of Applied Cryptography 4.81)
         */
        do {
            BigInteger h = BigIntegers.createRandomInRange(TWO, pMinusTwo, random);
            g = h.modPow(TWO, p);

            ThreadUtilities.ifInterruptedStop();
        } while (g.equals(BigInteger.ONE));

        return g;
    }

    public static void main(String[] args)
            throws Exception {
        Provider.set();

        BigInteger p = generateP(512);
        System.out.println(p);
        testP(p);
    }

    private static void testP(BigInteger p) {
        System.out.println(p.bitLength());
        System.out.println("  p.isProbablePrime(80): " + p.isProbablePrime(80));
        BigInteger q = p.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2));
        System.out.println("  q.isProbablePrime(80): " + q.isProbablePrime(80));
    }
}




package gui;

import crypto.KeyGenerator;

import java.io.File;
import java.util.Date;

/**
 * Wraps key generation to be executed in the background.
 *
 * @author Jose A. Manas
 * @version 20.8.2014
 */
public class KeyGeneratingThread
        extends Thread {
    private KeyGenerator keyGenerator;

    private String result;
    private long delta;
    private Exception executionException;

    public KeyGeneratingThread(
            File directory,
            String signAlgo, int signSize,
            String encryptAlgo, int encryptSize,
            String name, String email, String comment,
            Date expireDate,
            char[] password) {
        keyGenerator = new KeyGenerator(
                directory,
                signAlgo, signSize,
                encryptAlgo, encryptSize,
                name, email, comment,
                expireDate,
                password);
    }

    @Override
    public void run() {
        long t1 = System.currentTimeMillis();
        try {
            result = keyGenerator.generate();
        } catch (Exception e) {
            executionException = e;
        }
        long t2 = System.currentTimeMillis();
        delta = (t2 - t1) / 1000;
    }

    public String getResult() {
        return result;
    }

    public Exception getExecutionException() {
        return executionException;
    }

    public long getDelta() {
        return delta;
    }
}

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

    KeyGeneratingThread(
            File directory,
            String signAlgo,
            String encryptAlgo,
            String name, String email, String comment,
            Date expireDate,
            char[] password) {
        keyGenerator = new KeyGenerator(
                directory,
                signAlgo, encryptAlgo,
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

    String getResult() {
        return result;
    }

    Exception getExecutionException() {
        return executionException;
    }

    long getDelta() {
        return delta;
    }
}

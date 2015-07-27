package gui;

/**
 * @author Jose A. Manas
 * @version 16.8.2014
 */
public class ThreadUtilities {
    public static void ifInterruptedStop()
            throws InterruptedException {
        // give others a chance ...
        Thread.yield();
        if (Thread.currentThread().isInterrupted())
            throw new InterruptedException("Stopped by ifInterruptedStop()");
    }
}

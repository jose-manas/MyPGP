package exception;

/**
 * Cancelled pasword.
 *
 * @author Jose A. Manas
 * @version 28.10.2008
 */
public class PasswordCancelled
        extends Exception {
    public PasswordCancelled() {
        super("exception.password_cancelled");
    }
}

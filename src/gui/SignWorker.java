package gui;

import bc.BcUtilsFiles;
import exception.MyLogger;
import keys.Key;
import org.bouncycastle.openpgp.PGPException;

import javax.swing.*;
import java.io.File;
import java.util.List;
import java.util.Map;
import java.util.Random;

public class SignWorker
        extends SwingWorker<Void, String>
        implements MyWorker {
    private final String action;
    private final File[] files;
    private final List<Key> signingKeys;
    private final Map<Key, char[]> passwords;
    private final boolean armor;

    public SignWorker(String action,
                      File[] files,
                      List<Key> signingKeys,
                      Map<Key, char[]> passwords,
                      boolean armor) {
        this.action = action;
        this.files = files;
        this.signingKeys = signingKeys;
        this.passwords = passwords;
        this.armor = armor;
    }

    @Override
    protected Void doInBackground() {
        for (File redFile : files) {
            try {
                publish(redFile.getName());
                BcUtilsFiles.sign(redFile, signingKeys, passwords, armor, this);
            } catch (PGPException e) {
                publish(e.toString());
                if (e.getUnderlyingException() != null)
                    MyLogger.dump(e.getUnderlyingException(), action);
            } catch (Exception e) {
                MyLogger.dump(e, action);
            }
        }
        return null;
    }

    @Override
    public void topublish(String msg) {
        publish(msg);
    }

    @Override
    public void topublish(SignedItem msg) {
    }

    @Override
    protected void process(List<String> chunks) {
        for (String chunk : chunks)
            LogWindow.add(chunk);
    }

    @Override
    protected void done() {

        for (char[] password : passwords.values())
            clearPassword(password);
    }

    private static void clearPassword(char[] password) {
        Random random = new Random();
        for (int i = 0; i < password.length; i++) {
            char c = (char) ('a' + random.nextInt('z' - 'a' + 1));
            password[i] = c;
        }
    }
}

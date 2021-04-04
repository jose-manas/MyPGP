package gui;

import bc.BcUtilsFiles;
import exception.MyLogger;
import exception.PasswordCancelled;
import keys.Key;
import org.bouncycastle.openpgp.PGPException;
import sun.rmi.runtime.Log;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

public class DecryptVerifyWorker
        extends SwingWorker<Void, Object>
        implements MyWorker {
    private final String action;
    private final File[] files;
    private final Map<Long, char[]> passwords;

    public DecryptVerifyWorker(String action, File[] files) {
        this.action = action;
        this.files = files;
        this.passwords = new HashMap<>();
    }

    @Override
    protected Void doInBackground() {
        for (File blackFile : files) {
            try {
                BcUtilsFiles.process(blackFile, passwords, this);
            } catch (PasswordCancelled ignored) {
            } catch (PGPException e) {
                publish(e.toString());
                if (e.getUnderlyingException() != null)
                    MyLogger.dump(e.getUnderlyingException(), Text.get("process"));
            } catch (Exception e) {
                MyLogger.dump(e, Text.get("process"));
            }
        }
        return null;
    }

    @Override
    public void topublish(String object) {
        publish(object);
    }

    @Override
    public void topublish(SignedItem object) {
        publish(object);
    }

    @Override
    protected void process(List<Object> reportList) {
        for (Object report : reportList) {
            if (report instanceof String) {
                LogWindow.add((String)report);
            }
            if (report instanceof SignedItem) {
                SignedItem item= (SignedItem) report;
                LogWindow.signature(item.verify, item.signer, item.file);
            }
        }
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

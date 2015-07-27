package crypto;

import exception.PasswordCancelled;
import gui.Text;
import gui.imgs.Icons;
import labelleditem.LabelledItemPanel;

import javax.swing.*;
import java.util.Arrays;

/**
 * Reading and writing keys.
 *
 * @author Jose A. Manas
 * @version 14.4.2009
 */
public class GetPassword {
    private static GetPassword instance = new GetPassword();

    public static GetPassword getInstance() {
        return instance;
    }

    // last password known
    private char[] last;

    // for encrypting
    private final JPasswordField pw1 = new JPasswordField(40);
    private final JPasswordField pw2 = new JPasswordField(40);

    // for decrypting
    private final JPasswordField pw3 = new JPasswordField(40);

    private final JPanel encryptingPanel;
    private final JPanel decryptingPanel;

    /**
     * Constructor.
     */
    private GetPassword() {
        encryptingPanel = mkEncryptingPanel();
        decryptingPanel = mkDecryptingPanel();
    }

    private JPanel mkEncryptingPanel() {
        LabelledItemPanel panel = new LabelledItemPanel();
        panel.addItem(Text.get("password") + ": ", pw1);
        panel.addItem(Text.get("confirm") + ": ", pw2);
        return panel;
    }

    private JPanel mkDecryptingPanel() {
        LabelledItemPanel panel = new LabelledItemPanel();
        panel.addItem(Text.get("password") + ": ", pw3);
        return panel;
    }

    /**
     * Encrypting.
     *
     * @throws PasswordCancelled password cancelled.
     */
    public char[] getEncryptionPassword()
            throws PasswordCancelled {
        if (last != null) {
            String old = new String(last);
            pw1.setText(old);
            pw2.setText(old);
        }

        while (true) {
            int ret = JOptionPane.showConfirmDialog(null,
                    encryptingPanel, Text.get("encrypt"),
                    JOptionPane.OK_CANCEL_OPTION,
                    JOptionPane.QUESTION_MESSAGE,
                    Icons.getPgpIcon());
            if (ret != JOptionPane.OK_OPTION)
                throw new PasswordCancelled();
            if (Arrays.equals(pw1.getPassword(), pw2.getPassword())) {
                last = mkCopy(pw1.getPassword());
                pw1.setText("");
                pw2.setText("");
                return mkCopy(last);
            }
        }
    }

    /**
     * Decrypting.
     *
     * @throws PasswordCancelled password cancelled.
     */
    public char[] getDecryptionPassword(String label)
            throws PasswordCancelled {
        int ret = JOptionPane.showConfirmDialog(null,
                decryptingPanel, label,
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.QUESTION_MESSAGE,
                Icons.getPgpIcon());
        last = pw3.getPassword();
        // never return your material: people might clean it!
        pw3.setText("");
        if (ret != JOptionPane.OK_OPTION)
            throw new PasswordCancelled();
        return mkCopy(last);
    }

    /**
     * Char array clone.
     *
     * @param original original
     * @return copia
     */
    private char[] mkCopy(char[] original) {
        if (original == null)
            return null;
        return original.clone();
    }
}

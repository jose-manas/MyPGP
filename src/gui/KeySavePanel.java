package gui;

import keys.Key;
import labelleditem.LabelledItemPanel;

import javax.swing.*;
import java.util.Arrays;

/**
 * @author Jose A. Manas
 * @version 28.9.2014
 */
public class KeySavePanel
        extends LabelledItemPanel {
    private final JPasswordField pw1 = new JPasswordField(40);
    private final JPasswordField pw2 = new JPasswordField(40);

    public KeySavePanel(Key key) {
        addItem(Text.get("name"), new JLabel(key.toString()));
        addItem(mandatory("password"), pw1);
        addItem(mandatory("confirm"), pw2);
    }

    private String mandatory(String key) {
        return Text.get(key) + " (*)";
    }

    public char[] getPassword() {
        char[] password1 = pw1.getPassword();
        char[] password2 = pw2.getPassword();
        if (Arrays.equals(password1, password2))
            return password1;
        return null;
    }
}

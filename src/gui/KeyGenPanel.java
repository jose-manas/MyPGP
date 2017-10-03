package gui;

import labelleditem.LabelledItemPanel;

import javax.swing.*;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;

// 8.6.2011 mark mandatory fields

/**
 * @author Jose A. Manas
 * @version 2.5.2011
 */
public class KeyGenPanel
        extends LabelledItemPanel {
    private final JTextField nameField = new JTextField(40);
    private final JTextField commentField = new JTextField(40);
    private final JTextField emailField = new JTextField(40);
    private final JTextField expireField = new JTextField(40);
    private final JPasswordField pw1 = new JPasswordField(40);
    private final JPasswordField pw2 = new JPasswordField(40);

    private final AlgoPanel2 algoPanel;

    KeyGenPanel() {
        algoPanel = new AlgoPanel2();

        addItem(mandatory("name"), nameField);
        addItem(optional("comment"), commentField);
        addItem(mandatory("email"), emailField);
        addItem(Text.get("algorithms"), algoPanel);
        addItem(optional("expire"), expireField);
        addItem(mandatory("password"), pw1);
        addItem(mandatory("confirm"), pw2);
    }

    private String mandatory(String key) {
        return Text.get(key) + " (*)";
    }

    private String optional(String key) {
        return Text.get(key);
    }

    public String getName() {
        return nameField.getText().trim();
    }

    public String getComment() {
        String text = commentField.getText().trim();
        if (text.length() == 0)
            return "";
        text = text.replaceAll("\\(", "").replaceAll("\\)", "");
        return text.trim();
    }

    String getEmail() {
        String text = emailField.getText().trim();
        if (text.length() == 0)
            return "";
        text = text.replaceAll("<", "").replaceAll(">", "");
        return text.trim();
    }

    Date getExpireDate() {
        String text = expireField.getText().trim();
        if (text.length() == 0) {
            // yesterday
            Calendar cal = Calendar.getInstance();
            cal.setTime(new Date());
            cal.add(Calendar.DAY_OF_MONTH, -1);
            return cal.getTime();
        }
        try {
            DateFormat sourceFormat = new SimpleDateFormat("d.M.y");
            return sourceFormat.parse(text);
        } catch (Exception ignored) {
        }
        try {
            DateFormat sourceFormat = new SimpleDateFormat("d/M/y");
            return sourceFormat.parse(text);
        } catch (Exception ignored) {
        }
        try {
            DateFormat sourceFormat = new SimpleDateFormat("d-M-y");
            return sourceFormat.parse(text);
        } catch (Exception ignored) {
        }
        return null;
    }

    public char[] getPassword() {
        char[] password1 = pw1.getPassword();
        char[] password2 = pw2.getPassword();
        if (Arrays.equals(password1, password2))
            return password1;
        return null;
    }

    String getSignAlgo() {
        return algoPanel.getSignAlgo();
    }

    String getEncryptAlgo() {
        return algoPanel.getEncryptAlgo();
    }
}

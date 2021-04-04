package gui;

import gui.imgs.Icons;
import keys.Key;

import javax.swing.*;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;

/**
 * @author Jose A. Manas
 * @version 27.1.2020
 */
public class LogWindow {
    private static JFrame frame;
    private static JTextArea LOG_AREA;

    private static void init() {
        if (frame == null) {
            frame = new JFrame(Version.VERSION);
            frame.setIconImage(Icons.getPgpImage());
            frame.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
            frame.addWindowListener(new WindowAdapter() {
                @Override
                public void windowClosed(WindowEvent e) {
                    frame = null;
                }
            });

            LOG_AREA = new JTextArea();
            LOG_AREA.setWrapStyleWord(true);
            LOG_AREA.setLineWrap(true);
            frame.add(new JScrollPane(LOG_AREA));

            GraphicsEnvironment graphicsEnvironment = GraphicsEnvironment.getLocalGraphicsEnvironment();
            Rectangle total = graphicsEnvironment.getMaximumWindowBounds();
            frame.setSize(total.width / 2, total.height / 2);
            frame.setLocation(100, 100);

            frame.setVisible(true);
        }
    }

    public static void log(String s) {
        init();
        LOG_AREA.append(String.format("%s\n", s));
    }

    public static void log() {
        init();
        LOG_AREA.append("\n");
    }

    public static void pub(Key key) {
        add(String.format("  %s: %s",
                Text.get("public_keys"),
                key.toString()));
    }

    public static void encryptingFor(Key key) {
        add(String.format("  %s: %s",
                Text.get("encrypt"),
                key.toString()));
    }
    public static void encryptedFor(Key key) {
        add(String.format("  %s: %s",
                Text.get("encypted_for"),
                key.toString()));
    }

    public static void secret(Key key) {
        add(String.format("  %s: %s",
                Text.get("secret_keys"),
                key.toString()));
    }

    public static void signer(Key key) {
        add(String.format("  %s: %s",
                Text.get("signer"),
                key.toString()));
    }

    public static void add(String s) {
        init();
        LOG_AREA.append(String.format("%s%n", s));
        LOG_AREA.setCaretPosition(LOG_AREA.getDocument().getLength());
    }

    public static void add(Exception e) {
        add(e.toString());
    }

    public static void signature(boolean verify, Key signer, File file) {
        String message = verify ? Text.get("signature_ok") : Text.get("signature_bad");
        LogWindow.add(message);

        JLabel label = new JLabel();
        label.setOpaque(true);
        label.setBackground(verify ? Color.GREEN : Color.RED);
        label.setBorder(BorderFactory.createEmptyBorder(10, 20, 10, 20));
        JDialog dialog = new JDialog(MyPGP.getWindow());
        if (file == null) {
            dialog.setTitle(Text.get("clipboard"));
            label.setText(String.format("<html><p align=\"center\">%s<br><br>%s",
                    message, escapeHTML(signer.toString())));
        } else {
            dialog.setTitle(message);
            label.setText(String.format("<html><p align=\"center\">%s<br><br>%s",
                    file.getName(), escapeHTML(signer.toString())));
        }
        dialog.add(label);
        dialog.pack();
        dialog.setLocationRelativeTo(MyPGP.getWindow());
        dialog.setVisible(true);
    }

    private static String escapeHTML(String s) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c > 127 || c == '"' || c == '<' || c == '>' || c == '&')
                out.append("&#").append((int) c).append(';');
            else
                out.append(c);
        }
        return out.toString();
    }
}

package gui;

import gui.imgs.Icons;
import keys.Key;

import javax.swing.*;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.ArrayList;

/**
 * @author Jose A. Manas
 * @version 27.1.2020
 */
public class LogWindow {
    private static JFrame frame;
    private static JTextArea LOG_AREA;
    private static Item item;

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

    public static void print(Item item) {
        init();
        if (item.command != null)
            LOG_AREA.append(String.format("%s\n", item.command));
        if (item.publicKeyList.size() > 0) {
            LOG_AREA.append(String.format("  %s\n", Text.get("public_keys")));
            for (Key key: item.publicKeyList)
                LOG_AREA.append(String.format("    %s\n", key.toString()));
        }
        if (item.secretKeyList.size() > 0) {
            LOG_AREA.append(String.format("  %s\n", Text.get("secret_keys")));
            for (Key key: item.secretKeyList)
                LOG_AREA.append(String.format("    %s\n", key.toString()));
        }
        for (String s: item.textList)
            LOG_AREA.append(String.format("  %s\n", s));
        LOG_AREA.append("\n");
        LOG_AREA.setCaretPosition(LOG_AREA.getDocument().getLength());
    }

    public static void log(String s) {
        init();
        LOG_AREA.append(String.format("%s\n", s));
    }

    public static void log() {
        init();
        LOG_AREA.append("\n");
    }

    public static void openItem(String s) {
        if (item != null)
            print(item);
        item = new Item(s);
    }

    public static void closeItem() {
        if (item == null)
            return;
        print(item);
        item = null;
    }

    public static void addPublic(Key key) {
        if (item == null)
            item= new Item();
            item.addPublic(key);
    }

    public static void addSecret(Key key) {
        if (item == null)
            item= new Item();
            item.addSecret(key);
    }

    public static void add(String s) {
        if (item == null)
            item = new Item(s);
        else
            item.add(s);
    }

    public static void add(Exception e) {
        add(e.toString());
    }

    public static class Item {
        private final String command;
        private java.util.List<Key> publicKeyList = new ArrayList<>();
        private java.util.List<Key> secretKeyList = new ArrayList<>();
        private java.util.List<String> textList = new ArrayList<>();

        public Item(String command) {
            this.command = command;
        }

        public Item() {
            this.command= null;
        }

        public void addPublic(Key key) {
            publicKeyList.add(key);
        }

        public void addSecret(Key key) {
            secretKeyList.add(key);
        }

        public void add(String text) {
            textList.add(text);
        }

        public String toString() {
            if (command != null)
                return command;
            else
                return "no command";
        }
    }
}

package exception;

import gui.Version;
import gui.imgs.Icons;

import javax.swing.*;
import java.io.File;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * @author Jose A. Manas
 * @version 8.5.2015
 */
public class MyLogger {
    private static final SimpleDateFormat DATE = new SimpleDateFormat("HHmmss");

    public static void record(Throwable e) {
        try {
            String home = System.getProperty("user.home");
            String filename = String.format("mypgp_%s.txt", DATE.format(new Date()));
            File file = new File(home, filename);
            PrintWriter writer = new PrintWriter(file);
            writer.println(Version.VERSION);
            e.printStackTrace(writer);
            writer.close();
        } catch (Exception ignored) {
        }

    }

    public static void dump(Exception e, String message) {
        record(e);
        JOptionPane.showMessageDialog(null,
                e,
                message,
                JOptionPane.ERROR_MESSAGE,
                Icons.getPgpIcon());
    }
}

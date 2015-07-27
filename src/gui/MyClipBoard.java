package gui;

import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Transferable;

/**
 * @author Jose A. Manas
 * @version 13.2.2009
 */
public class MyClipBoard {
    private static Clipboard clipboard;

    public static void write(String s) {
        if (clipboard == null)
            clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        Transferable transferable = new StringSelection(s);
        clipboard.setContents(transferable, null);
    }

    public static String readString() {
        if (clipboard == null)
            clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        Transferable transferable = clipboard.getContents(null);
        try {
            return (String) (transferable.getTransferData(DataFlavor.stringFlavor));
        } catch (Exception ee) {
            return ee.toString();
        }
    }
}

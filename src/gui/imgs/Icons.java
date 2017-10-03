package gui.imgs;

import javax.swing.*;
import java.awt.*;
import java.net.URL;

/**
 * @author Jose A. Manas
 * @version 21.8.2014
 */
public class Icons {
    private static ImageIcon pgpIcon16;
    private static ImageIcon pgpIcon32;

    private static ImageIcon closedIcon;
    private static ImageIcon computerIcon;
    private static ImageIcon diskIcon;
    private static ImageIcon keyIcon;
    private static ImageIcon listIcon;
    private static ImageIcon openIcon;
    private static ImageIcon textIcon;
    private static ImageIcon noneIcon;
    private static ImageIcon partialIcon;
    private static ImageIcon fullIcon;

    public static Image getPgpImage() {
        if (pgpIcon16 == null)
            pgpIcon16 = loadIcon("lock.png");
        return pgpIcon16.getImage();
    }

    public static Icon getClosedIcon() {
        if (closedIcon == null)
            closedIcon = loadIcon("closed.png");
        return closedIcon;
    }

    public static Icon getComputerIcon() {
        if (computerIcon == null)
            computerIcon = loadIcon("computer.png");
        return computerIcon;
    }

    public static Icon getDiskIcon() {
        if (diskIcon == null)
            diskIcon = loadIcon("disk.png");
        return diskIcon;
    }

    public static Icon getKeyIcon() {
        if (keyIcon == null)
            keyIcon = loadIcon("key.png");
        return keyIcon;
    }

    public static Icon getListIcon() {
        if (listIcon == null)
            listIcon = loadIcon("list.png");
        return listIcon;
    }

    public static Icon getLockIcon() {
        if (pgpIcon16 == null)
            pgpIcon16 = loadIcon("lock.png");
        return pgpIcon16;
    }

    public static Icon getOpenIcon() {
        if (openIcon == null)
            openIcon = loadIcon("open.png");
        return openIcon;
    }

    public static Icon getPgpIcon() {
        if (pgpIcon32 == null)
            pgpIcon32 = loadIcon("lock_32.png");
        return pgpIcon32;
    }

    public static Icon getTextIcon() {
        if (textIcon == null)
            textIcon = loadIcon("text.png");
        return textIcon;
    }

    public static Icon getNoneSelectionIcon() {
        if (noneIcon == null)
            noneIcon = loadIcon("none.png");
        return noneIcon;
    }

    public static Icon getPartialSelectionIcon() {
        if (partialIcon == null)
            partialIcon = loadIcon("partial.png");
        return partialIcon;
    }

    public static Icon getFullSelectionIcon() {
        if (fullIcon == null)
            fullIcon = loadIcon("full.png");
        return fullIcon;
    }

    private static ImageIcon loadIcon(String name) {
        Class imgs = Icons.class;
        try {
            URL url = imgs.getResource(name);
            return new ImageIcon(url);
        } catch (Exception e) {
            System.err.println("no "
                    + imgs.getPackage().getName()
                    + System.getProperty("file.separator")
                    + name);
            return null;
        }
    }
}

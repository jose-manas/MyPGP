package gui;

import javax.swing.*;
import java.awt.*;
import java.io.File;

/**
 * Selects a red file to write when first option already exists.
 *
 * @author Jose A. Manas
 * @version 30.12.2016
 */
public class FilePanel
        extends JPanel {
    private JCheckBox box1;
    private JCheckBox box2;
    private final File ovwFile;
    private File newFile;

    public FilePanel(File file) {
        String base = file.getName();
        String ext = ".out";
        String fileName = file.getName();
        int dot = fileName.lastIndexOf('.');
        if (dot > 0) {
            base = fileName.substring(0, dot);
            ext = fileName.substring(dot);      // starting dot
        }
        ovwFile = file;
        newFile = ovwFile;
        int v = 2;
        while (newFile.exists()) {
            newFile = new File(
                    file.getParent(),
                    String.format("%s_%d%s", base, v++, ext));
        }

        setup();
    }

    public FilePanel(File base, String ext) {
        ovwFile = new File(base.getParent(), base.getName() + ext);
        newFile = ovwFile;
        int v = 2;
        while (newFile.exists()) {
            newFile = new File(
                    base.getParent(),
                    String.format("%s_%d%s", base.getName(), v++, ext));
        }

        setup();
    }

    private void setup() {
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        ButtonGroup group = new ButtonGroup();
        box1 = new JCheckBox(Text.get("overwrite") + ": " + ovwFile);
        box2 = new JCheckBox(Text.get("new") + ": " + newFile);
        group.add(box1);
        group.add(box2);
        box1.setSelected(true);

        box1.setAlignmentX(Component.LEFT_ALIGNMENT);
        box2.setAlignmentX(Component.LEFT_ALIGNMENT);
        add(box1);
        add(box2);
    }

    public File getOvwFile() {
        return ovwFile;
    }

    public File getSelectedFile() {
        if (box1.isSelected())
            return ovwFile;
        else
            return newFile;
    }
}

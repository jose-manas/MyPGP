package gui;

import exception.PasswordCancelled;
import gui.imgs.Icons;

import javax.swing.*;
import java.awt.*;

/**
 * Ask whether text (armored) or binary for crypto files.
 *
 * @author Jose A. Manas
 * @version 30.12.2016
 */
class ArmorPanel
        extends JPanel {
    private JCheckBox box1;
    private JCheckBox box2;

    private ArmorPanel(boolean armor, String b_ext) {
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        ButtonGroup group = new ButtonGroup();
        box1 = new JCheckBox(Text.get("text") + ": .asc");
        box2 = new JCheckBox(Text.get("binary") + ": " + b_ext);
        group.add(box1);
        group.add(box2);
        if (armor)
            box1.setSelected(true);
        else
            box2.setSelected(true);

        box1.setAlignmentX(Component.LEFT_ALIGNMENT);
        box2.setAlignmentX(Component.LEFT_ALIGNMENT);
        add(box1);
        add(box2);
    }

    private boolean isArmor() {
        return box1.isSelected();
    }

    static boolean getArmor(String op, boolean armor, String b_ext)
            throws PasswordCancelled {
        ArmorPanel panel = new ArmorPanel(armor, b_ext);
        int ret = JOptionPane.showConfirmDialog(null,
                panel, op,
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.QUESTION_MESSAGE,
                Icons.getPgpIcon());
        if (ret != JOptionPane.OK_OPTION)
            throw new PasswordCancelled();
        return panel.isArmor();

    }
}

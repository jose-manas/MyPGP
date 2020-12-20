package gui;

import gui.imgs.Icons;
import keys.Directory;
import keys.Key;
import keys.KeyList;

import javax.swing.*;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreeCellRenderer;
import java.awt.*;
import java.util.Set;

/**
 * @author Jose A. Manas
 * @version 29.9.2017
 */
public class MyTreeRenderer
        implements TreeCellRenderer {
    private final Set<Object> selection;
    private Box panel;
    private JLabel label_1;
    private JLabel label_2;
    private JLabel label;

    MyTreeRenderer(Set<Object> selection) {
        this.selection = selection;
        label = new JLabel();

        panel = Box.createHorizontalBox();
        label_1 = new JLabel();
        label_2 = new JLabel();
        label_2.setOpaque(true);
        panel.add(label_1);
        panel.add(Box.createHorizontalStrut(2));
        panel.add(label_2);
    }

    public Component getTreeCellRendererComponent(JTree tree, Object value,
                                                  boolean selected, boolean expanded,
                                                  boolean leaf, int row, boolean hasFocus) {
        try {
            if (selected) {
                label_2.setBackground(Color.blue);
                label_2.setForeground(Color.white);
            } else {
                label_2.setBackground(Color.white);
                label_2.setForeground(Color.darkGray);
            }

            DefaultMutableTreeNode node = (DefaultMutableTreeNode) value;
            Object x = node.getUserObject();
            if (x instanceof Key)
                return getRenderer((Key) x, getSelection(node));
            if (x instanceof Directory)
                return getRenderer((Directory) x, getSelection(node), expanded);
            if (x instanceof KeyList)
                return getRenderer((KeyList) x, getSelection(node));
            label.setText(x.toString());
            if (leaf) {
                if (x instanceof String)
                    label.setIcon(Icons.getTextIcon());
            } else {
                if (expanded)
                    label.setIcon(Icons.getOpenIcon());
                else
                    label.setIcon(Icons.getClosedIcon());
            }
        } catch (Exception ignored) {
        }
        return label;
    }

    private Icon getSelection(DefaultMutableTreeNode node) {
        Object x = node.getUserObject();
        if (selection.contains(node))
            return Icons.getFullSelectionIcon();
        int children = node.getChildCount();
        int selected = 0;
        for (int ch = 0; ch < children; ch++) {
            DefaultMutableTreeNode child = (DefaultMutableTreeNode) node.getChildAt(ch);
            Icon chi = getSelection(child);
            if (chi == Icons.getFullSelectionIcon())
                selected++;
        }
        if (selected == 0)
            return Icons.getNoneSelectionIcon();
        if (selected < children)
            return Icons.getPartialSelectionIcon();
        return Icons.getFullSelectionIcon();
    }

    private Component getRenderer(Key key, Icon selected) {
        label_1.setIcon(selected);
        label_2.setIcon(Icons.getKeyIcon(key));
        label_2.setText(key.toString());
        return panel;
    }

    private Component getRenderer(Directory directory, Icon selected, boolean expanded) {
        label_1.setIcon(selected);
        if (expanded)
            label_2.setIcon(Icons.getOpenIcon());
        else
            label_2.setIcon(Icons.getClosedIcon());
        label_2.setText(directory.toString());
        return panel;
    }

    private Component getRenderer(KeyList keyList, Icon selected) {
        label_1.setIcon(selected);
        label_2.setIcon(Icons.getListIcon());
        label_2.setText(keyList.toString());
        return panel;
    }
}

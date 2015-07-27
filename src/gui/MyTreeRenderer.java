package gui;

import gui.imgs.Icons;
import keys.Key;
import keys.KeyList;

import javax.swing.*;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;
import java.awt.*;

/**
 * @author Jose A. Manas
 * @version 21.8.2014
 */
public class MyTreeRenderer
        extends DefaultTreeCellRenderer {
    public Component getTreeCellRendererComponent(JTree tree, Object value,
                                                  boolean selected, boolean expanded,
                                                  boolean leaf, int row, boolean hasFocus) {
        Component c = super.getTreeCellRendererComponent(tree, value, selected, expanded, leaf, row, hasFocus);
        try {
            DefaultMutableTreeNode node = (DefaultMutableTreeNode) value;
            Object x = node.getUserObject();
            if (x instanceof Key)
                setIcon(Icons.getKeyIcon());
            else if (x instanceof KeyList)
                setIcon(Icons.getListIcon());
            else if (leaf) {
                if (x instanceof String)
                    setIcon(Icons.getTextIcon());
            } else {
                if (expanded)
                    setIcon(Icons.getOpenIcon());
                else
                    setIcon(Icons.getClosedIcon());
            }
        } catch (Exception ignored) {
        }
        return c;
    }
}

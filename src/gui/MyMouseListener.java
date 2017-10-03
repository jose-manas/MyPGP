package gui;

import keys.Directory;
import keys.Key;
import keys.KeyList;

import javax.swing.*;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreePath;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.Set;

/**
 * @author Jose A. Manas
 * @version 29.9.2017
 */
public class MyMouseListener
        extends MouseAdapter {
    private final JTree keysTree;
    private final Set<Object> selection;

    private JPopupMenu popupKeyInRings;
    private JPopupMenu popupKeyInList;
    private JPopupMenu popupList;

    MyMouseListener(JTree keysTree, Set<Object> selection) {
        this.keysTree = keysTree;
        this.selection = selection;
    }

    @Override
    public void mousePressed(MouseEvent me) {
        if (me.getButton() == MouseEvent.BUTTON1)
            pressed1(me);
        if (me.getButton() == MouseEvent.BUTTON3)
            pressed3(me);
    }

    private void pressed1(MouseEvent me) {
        int x = me.getX();
        int y = me.getY();
        int row = keysTree.getRowForLocation(x, y);
        if (row < 0)
            return;
        TreePath path = keysTree.getPathForRow(row);
        if (path == null)
            return;
        DefaultMutableTreeNode node = (DefaultMutableTreeNode) path.getLastPathComponent();
        Object object = node.getUserObject();
        if (object instanceof Key)
            toggle(node);
        if (object instanceof Directory)
            toggle(node);
        if (object instanceof KeyList)
            toggle(node);
        keysTree.repaint();
    }

    private void toggle(Object object) {
        if (selection.contains(object))
            selection.remove(object);
        else
            selection.add(object);
    }

    private void pressed3(MouseEvent me) {
        int x = me.getX();
        int y = me.getY();
        int row = keysTree.getRowForLocation(x, y);
        if (row < 0)
            return;
        TreePath path = keysTree.getPathForRow(row);
        if (path == null)
            return;
        keysTree.setSelectionPath(path);
        if (keyInSecretList(path))
            doKeyInSecretList(x, y);
        else if (isList(path))
            doList(x, y);
        else if (keyInList(path))
            doKeyInList(x, y);
        else if (isKey(path))
            doKeyInPublicList(x, y);
    }

    private static boolean keyInSecretList(TreePath path) {
        DefaultMutableTreeNode last = (DefaultMutableTreeNode) path.getLastPathComponent();
        Object x = last.getUserObject();
        if (x.getClass() != Key.class)
            return false;
        DefaultMutableTreeNode node = (DefaultMutableTreeNode) path.getPathComponent(path.getPathCount() - 2);
        return node == MyPGP.getSecKeyBranch();
    }

    private boolean isKey(TreePath path) {
        DefaultMutableTreeNode last = (DefaultMutableTreeNode) path.getLastPathComponent();
        Object x = last.getUserObject();
        return x.getClass() == Key.class;
    }

    private boolean isList(TreePath path) {
        DefaultMutableTreeNode last = (DefaultMutableTreeNode) path.getLastPathComponent();
        Object x = last.getUserObject();
        return x.getClass() == KeyList.class;
    }

    private boolean keyInList(TreePath path) {
        DefaultMutableTreeNode last = (DefaultMutableTreeNode) path.getLastPathComponent();
        Object x = last.getUserObject();
        if (x.getClass() != Key.class)
            return false;
        DefaultMutableTreeNode node = (DefaultMutableTreeNode) path.getPathComponent(path.getPathCount() - 2);
        return node.getUserObject().getClass() == KeyList.class;
    }

    private void doKeyInSecretList(int x, int y) {
        if (popupKeyInRings == null) {
            popupKeyInRings = new JPopupMenu();
            popupKeyInRings.add(new MyPGP.AliasKeyAction(false));
            popupKeyInRings.add(new MyPGP.CopyKeyAction(false));
            popupKeyInRings.add(new MyPGP.ExportKeyAction(false));
        }
        popupKeyInRings.show(keysTree, x, y);
    }

    private void doKeyInPublicList(int x, int y) {
        if (popupKeyInRings == null) {
            popupKeyInRings = new JPopupMenu();
            popupKeyInRings.add(new MyPGP.AliasKeyAction(false));
            popupKeyInRings.add(new MyPGP.CopyKeyAction(false));
            popupKeyInRings.add(new MyPGP.ExportKeyAction(false));
        }
        popupKeyInRings.show(keysTree, x, y);
    }

    private void doList(int x, int y) {
        if (popupList == null) {
            popupList = new JPopupMenu();
//            popupList.add(new MyPGP.RemoveKeyListAction(false));
            popupList.add(new MyPGP.NewListAction());
            popupList.add(new MyPGP.RemoveListAction(false));
        }
        popupList.show(keysTree, x, y);
    }

    private void doKeyInList(int x, int y) {
        if (popupKeyInList == null) {
            popupKeyInList = new JPopupMenu();
            popupKeyInList.add(new MyPGP.AliasKeyAction(false));
            popupKeyInList.add(new MyPGP.CopyKeyAction(false));
            popupKeyInList.add(new MyPGP.ExportKeyAction(false));
            popupKeyInList.add(new MyPGP.RemoveKeyListAction(false));
        }
        popupKeyInList.show(keysTree, x, y);
    }
}

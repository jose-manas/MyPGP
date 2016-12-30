package gui;

import exception.MyLogger;
import gui.imgs.Icons;

import javax.swing.*;
import javax.swing.event.TreeExpansionEvent;
import javax.swing.event.TreeExpansionListener;
import javax.swing.tree.*;
import java.awt.*;
import java.io.File;
import java.util.ArrayList;

/**
 * Created by jam on 06/03/2015.
 */
class MyDirectoryChooser
        extends JPanel {
    private static final int MDC_WIDTH = 400;
    private static final int MDC_HEIGHT = (int) (MDC_WIDTH / 1.6);

    private final DefaultTreeModel filesystemModel;
    private final JTree filesystemTree;

    MyDirectoryChooser() {
        super(new BorderLayout());
        DefaultMutableTreeNode top =
                new DefaultMutableTreeNode(
                        new IconData(Icons.getComputerIcon(), "Computer"));
        for (File root : File.listRoots()) {
            DefaultMutableTreeNode node =
                    new DefaultMutableTreeNode(
                            new IconData(Icons.getDiskIcon(), new FileNode(root)));
            top.add(node);
            node.add(new DefaultMutableTreeNode(true));
        }

        filesystemModel = new DefaultTreeModel(top);
        filesystemTree = new JTree(filesystemModel);
        filesystemTree.putClientProperty("JTree.lineStyle", "Angled");
        filesystemTree.setCellRenderer(new IconCellRenderer());
        filesystemTree.addTreeExpansionListener(new DirExpansionListener());
        filesystemTree.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
        filesystemTree.setShowsRootHandles(true);
        filesystemTree.setEditable(false);

        add(new JScrollPane(filesystemTree));
        setPreferredSize(new Dimension(MDC_WIDTH, MDC_HEIGHT));
    }

    public void setDirectory(String dirname) {
        setDirectory(new File(dirname));
    }

    public void setDirectory(File directory) {
        try {
            ArrayList<File> filePath = new ArrayList<>();
            for (File f = directory; f != null; f = f.getParentFile())
                filePath.add(0, f);
            DefaultMutableTreeNode found = find((DefaultMutableTreeNode) filesystemModel.getRoot(), filePath);
            TreePath treePath = new TreePath(found.getPath());
            filesystemTree.setSelectionPath(treePath);
            filesystemTree.scrollPathToVisible(treePath);
        } catch (Exception e) {
//            e.printStackTrace();
        }
    }

    private DefaultMutableTreeNode find(DefaultMutableTreeNode node, ArrayList<File> path) {
        File file = path.remove(0);
        Object userObject = node.getUserObject();
        IconData iconData = (IconData) userObject;
        Object object = iconData.getObject();
        if (object instanceof FileNode) {
            FileNode fileNode = (FileNode) object;
            fileNode.expand(node);
        }
        for (int ch = 0; ch < node.getChildCount(); ch++) {
            DefaultMutableTreeNode child = (DefaultMutableTreeNode) node.getChildAt(ch);
            if (getFile(child).equals(file)) {
                if (path.isEmpty())
                    return child;
                DefaultMutableTreeNode found = find(child, path);
                if (found != null)
                    return found;
            }
        }
        return null;
    }

    File getSelectedDirectory() {
        try {
            TreePath path = filesystemTree.getSelectionPath();
            DefaultMutableTreeNode node = getTreeNode(path);
            return getFile(node);
        } catch (Exception e) {
            return null;
        }
    }

    private File getFile(DefaultMutableTreeNode node) {
        IconData data = (IconData) node.getUserObject();
        FileNode fileNode = (FileNode) data.getObject();
        return fileNode.getFile();
    }

    private DefaultMutableTreeNode getTreeNode(TreePath path) {
        return (DefaultMutableTreeNode) path.getLastPathComponent();
    }

    private FileNode getFileNode(DefaultMutableTreeNode node) {
        try {
            IconData iconData = (IconData) node.getUserObject();
            return (FileNode) iconData.getObject();
        } catch (Exception e) {
            return null;
        }
    }

    private static class IconData {
        private final Icon icon;
        private final Icon expandedIcon;
        private final Object object;

        IconData(Icon icon, Object object) {
            this.icon = icon;
            expandedIcon = null;
            this.object = object;
        }

        IconData(Icon icon, Icon expandedIcon, Object data) {
            this.icon = icon;
            this.expandedIcon = expandedIcon;
            object = data;
        }

        public Icon getIcon() {
            return icon;
        }

        Icon getExpandedIcon() {
            return expandedIcon != null ? expandedIcon : icon;
        }

        public Object getObject() {
            return object;
        }

        public String toString() {
            return object.toString();
        }
    }

    private class FileNode {
        private final File file;

        FileNode(File file) {
            this.file = file;
        }

        public File getFile() {
            return file;
        }

        public String toString() {
            String name = file.getName();
            return name.length() > 0 ? name : file.getPath();
        }

        boolean expand(DefaultMutableTreeNode parent) {
            DefaultMutableTreeNode flag = (DefaultMutableTreeNode) parent.getFirstChild();
            if (flag == null)
                return false;
            Object obj = flag.getUserObject();
            if (!(obj instanceof Boolean))
                return false;

            parent.removeAllChildren();  // Remove Flag

            File[] files = listFiles();
            if (files == null)
                return true;

            ArrayList<FileNode> childList = new ArrayList<>();

            for (File child : files) {
                if (child.isDirectory())
                    insert(childList, new FileNode(child));
            }

            for (FileNode nd : childList) {
                IconData idata = new IconData(Icons.getClosedIcon(), Icons.getOpenIcon(), nd);
                DefaultMutableTreeNode node = new DefaultMutableTreeNode(idata);
                parent.add(node);

                if (nd.hasSubDirs())
                    node.add(new DefaultMutableTreeNode(true));
            }

            return true;
        }

        private void insert(ArrayList<FileNode> childList, FileNode newNode) {
            for (int i = 0; i < childList.size(); i++) {
                FileNode nd = childList.get(i);
                if (newNode.compareTo(nd) < 0) {
                    childList.add(i, newNode);
                    return;
                }
            }
            childList.add(newNode);
        }

        boolean hasSubDirs() {
            File[] files = listFiles();
            if (files == null)
                return false;
            for (File file : files) {
                if (file.isDirectory())
                    return true;
            }
            return false;
        }

        int compareTo(FileNode toCompare) {
            return file.getName().compareToIgnoreCase(toCompare.file.getName());
        }

        private File[] listFiles() {
            if (!file.isDirectory())
                return null;
            try {
                return file.listFiles();
            } catch (Exception ex) {
                MyLogger.record(ex);
                JOptionPane.showMessageDialog(null,
                        "Error reading directory " + file.getAbsolutePath(),
                        "Warning", JOptionPane.WARNING_MESSAGE);
                return null;
            }
        }
    }

    private static class IconCellRenderer
            extends JLabel
            implements TreeCellRenderer {
        private final Color textSelectionColor;
        private final Color textNonSelectionColor;
        private final Color bgSelectionColor;
        private final Color bgNonSelectionColor;
        private final Color borderSelectionColor;

        private boolean selected;

        IconCellRenderer() {
            textSelectionColor = UIManager.getColor("Tree.selectionForeground");
            textNonSelectionColor = UIManager.getColor("Tree.textForeground");
            bgSelectionColor = UIManager.getColor("Tree.selectionBackground");
            bgNonSelectionColor = UIManager.getColor("Tree.textBackground");
            borderSelectionColor = UIManager.getColor("Tree.selectionBorderColor");
            setOpaque(false);
        }

        public Component getTreeCellRendererComponent(JTree tree, Object value,
                                                      boolean sel, boolean expanded, boolean leaf,
                                                      int row, boolean hasFocus) {
            DefaultMutableTreeNode node = (DefaultMutableTreeNode) value;
            Object obj = node.getUserObject();
            setText(obj.toString());

            if (obj instanceof Boolean)
                setText("Retrieving data...");

            if (obj instanceof IconData) {
                IconData idata = (IconData) obj;
                if (expanded)
                    setIcon(idata.getExpandedIcon());
                else
                    setIcon(idata.getIcon());
            } else {
                setIcon(null);
            }

            setFont(tree.getFont());
            setForeground(sel ? textSelectionColor : textNonSelectionColor);
            setBackground(sel ? bgSelectionColor : bgNonSelectionColor);
            selected = sel;
            return this;
        }

        public void paintComponent(Graphics g) {
            Color bColor = getBackground();
            Icon icon = getIcon();

            g.setColor(bColor);
            int offset = 0;
            if (icon != null && getText() != null)
                offset = (icon.getIconWidth() + getIconTextGap());
            g.fillRect(offset, 0, getWidth() - 1 - offset, getHeight() - 1);

            if (selected) {
                g.setColor(borderSelectionColor);
                g.drawRect(offset, 0, getWidth() - 1 - offset, getHeight() - 1);
            }
            super.paintComponent(g);
        }
    }

    private class DirExpansionListener
            implements TreeExpansionListener {
        public void treeExpanded(TreeExpansionEvent event) {
            DefaultMutableTreeNode node = getTreeNode(event.getPath());
            FileNode fnode = getFileNode(node);
            if (fnode != null && fnode.expand(node))
                filesystemModel.reload(node);
        }

        public void treeCollapsed(TreeExpansionEvent event) {
        }
    }

}

package gui;

import gui.imgs.Icons;

import javax.swing.*;
import javax.swing.filechooser.FileSystemView;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.prefs.Preferences;
import java.util.regex.Pattern;

/**
 * Replacement for JFileChooser.
 * Portability to mac os x.
 *
 * @author jam
 * @version 6.3.2015
 */
public class MyFileChooser
        extends JPanel {
    public static final int COL_ICON = 0;
    public static final int COL_NAME = 1;
    public static final int COL_SIZE = 2;
    public static final int COL_DATE = 3;

    private final JTable table;
    private final FileTableModel tableModel;
    private BreadCrumb breadCrumb;
    private Preferences preferences;

    public MyFileChooser() {
        this(System.getProperty("user.home"));
    }

    public MyFileChooser(String dirname) {
        super(new BorderLayout());
        File directory = new File(dirname);

        tableModel = new FileTableModel(directory);
        table = new JTable(tableModel);
        Dimension dim = new Dimension(20, 1);
        table.setIntercellSpacing(new Dimension(dim));
        table.setGridColor(Color.LIGHT_GRAY);
        table.setRowHeight(20);
        table.setFillsViewportHeight(true);
        table.setAutoCreateRowSorter(true);

        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent event) {
                if (event.getClickCount() > 1) {
                    int row = table.rowAtPoint(event.getPoint());
                    File file = tableModel.getFile(table.convertRowIndexToModel(row));
                    if (file != null && file.isDirectory())
                        setDirectory(file);
                }
            }
        });

        table.setDefaultRenderer(Date.class, new MyDateRenderer());
        table.setDefaultRenderer(Long.class, new MySizeRenderer());

        table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        table.getColumnModel().getColumn(COL_ICON).setMaxWidth(40);
        table.getColumnModel().getColumn(COL_NAME).setPreferredWidth(200);
        table.getColumnModel().getColumn(COL_SIZE).setPreferredWidth(80);
        table.getColumnModel().getColumn(COL_DATE).setPreferredWidth(100);

        add(new JScrollPane(table));

        breadCrumb = new BreadCrumb(directory);
        add(breadCrumb, BorderLayout.SOUTH);
    }

    public void setPreferences(Preferences preferences) {
        this.preferences = preferences;
    }

    public void setDirectory(File directory) {
        try {
            preferences.put("working_dir", directory.getCanonicalPath());
        } catch (Exception ignored) {
        }

        tableModel.setDirectory(directory);
        tableModel.fireTableDataChanged();
        remove(breadCrumb);
        breadCrumb = new BreadCrumb(directory);
        add(breadCrumb, BorderLayout.SOUTH);
        revalidate();
    }

    private void setDirectory(File[] files) {
        tableModel.setDirectory(files);
        tableModel.fireTableDataChanged();
        remove(breadCrumb);
        breadCrumb = new BreadCrumb(tableModel.getDirectory());
        add(breadCrumb, BorderLayout.SOUTH);
        revalidate();
    }

    public void rescanCurrentDirectory() {
        setDirectory(tableModel.getDirectory());
    }

    public File[] getSelectedFiles() {
        int[] rows = table.getSelectedRows();
        File[] files = new File[rows.length];
        for (int i = 0; i < rows.length; i++)
            files[i] = tableModel.getFile(table.convertRowIndexToModel(rows[i]));
        return files;
    }

    public File getSelectedFile() {
        try {
            return getSelectedFiles()[0];
        } catch (Exception e) {
            return null;
        }
    }

    public File getCurrentDirectory() {
        return tableModel.getDirectory();
    }

    public void setSelectedFiles(File[] files) {
        table.clearSelection();
        if (tableModel.children == null)
            return;
        for (File file : files) {
            for (int i = 0; i < tableModel.children.length; i++) {
                File child = tableModel.children[i];
                if (child.equals(file)) {
                    int row = table.convertRowIndexToView(i);
                    table.addRowSelectionInterval(row, row);
                }
            }
        }
    }

    private class FileTableModel
            extends AbstractTableModel {
        private File[] children;

        private String[] columnNames = new String[]{
                "", Text.get("name"), Text.get("size"), Text.get("date")
        };

        protected Class[] columnClasses = new Class[]{
                Icon.class, String.class, Long.class, Date.class
        };
        private File directory;

        public FileTableModel(File directory) {
            setDirectory(directory);
        }

        public void setDirectory(File directory) {
            this.directory = directory;
            children = directory.listFiles();
        }

        public void setDirectory(File[] files) {
            directory = null;
            children = files;
        }

        public int getColumnCount() {
            return columnNames.length;
        }

        public int getRowCount() {
            if (children == null)
                return 0;
            return children.length;
        }

        @Override
        public String getColumnName(int col) {
            return columnNames[col];
        }

        @Override
        public Class getColumnClass(int col) {
            return columnClasses[col];
        }

        public Object getValueAt(int row, int col) {
            if (children == null || children[row] == null)
                return getDefaultValueAt(col);
            File file = children[row];
            switch (col) {
                case COL_ICON: {
                    if (file.isDirectory())
                        return Icons.getClosedIcon();
                    String name = file.getName().toLowerCase();
                    if (name.endsWith(".asc"))
                        return Icons.getLockIcon();
                    if (name.endsWith(".gpg"))
                        return Icons.getLockIcon();
                    if (name.endsWith(".pgp"))
                        return Icons.getLockIcon();
                    if (name.endsWith(".sig"))
                        return Icons.getLockIcon();
                    return FileSystemView.getFileSystemView().getSystemIcon(file);
                }
                case COL_NAME: {
                    String name = file.getName();
                    if (name.length() == 0)
                        return file.toString();
                    return name;
                }
                case COL_SIZE:
                    return file.length();
                case COL_DATE:
                    return new Date(file.lastModified());
                default:
                    return null;
            }
        }

        public Object getDefaultValueAt(int col) {
            switch (col) {
                case COL_ICON:
                    return null;
                case COL_NAME:
                    return "";
                case COL_SIZE:
                    return 0;
                case COL_DATE:
                    return new Date();
                default:
                    return null;
            }
        }

        public File getFile(int row) {
            if (children == null)
                return null;
            return children[row];
        }

        public File getDirectory() {
            return directory;
        }

    }

    private class BreadCrumb
            extends JPanel {
        private final String fs = System.getProperty("file.separator");

        public BreadCrumb(File directory) {
            super(new FlowLayout(FlowLayout.LEFT));
            add(mkButton(new JButton(Icons.getComputerIcon()), new JumpRoots()));
            if (directory == null)
                return;

            String path = null;
            try {
                path = directory.getCanonicalPath();
            } catch (Exception e) {
//                e.printStackTrace();
            }
            if (path == null)
                return;

            String[] names = path.split(Pattern.quote(fs));
            File running = null;
            for (String name : names) {
                if (running == null)
                    running = new File(name + fs);
                else
                    running = new File(running, name);
                if (name.length() == 0)
                    continue;
                if (getComponentCount() > 0)
                    add(new JLabel(fs));
                add(mkButton(new JButton(name), new Jumper(running)));
            }
        }

        private JButton mkButton(JButton button, Action action) {
            button.setForeground(Color.BLUE);
            button.setFocusPainted(false);
            button.setMargin(new Insets(0, 0, 0, 0));
            button.setContentAreaFilled(false);
            button.setBorderPainted(false);
            button.setOpaque(false);
            button.addActionListener(action);
            return button;
        }

        private class JumpRoots
                extends AbstractAction {
            public void actionPerformed(ActionEvent e) {
                setDirectory(File.listRoots());
            }
        }

        private class Jumper
                extends AbstractAction {
            private final File path;

            public Jumper(File path) {
                this.path = path;
            }

            public void actionPerformed(ActionEvent e) {
                setDirectory(path);
            }
        }
    }

    private class MySizeRenderer
            extends DefaultTableCellRenderer {
        public static final int K = 1024;

        public MySizeRenderer() {
            setHorizontalAlignment(SwingConstants.RIGHT);
        }

        @Override
        public void setValue(Object value) {
            try {
                Long bytes = (Long) value;
                super.setValue(mkString(bytes));
            } catch (Exception e) {
                super.setValue(value);
            }
        }

        private String mkString(long bytes) {
            if (bytes < K)
                return bytes + " B";
            int exp = (int) (Math.log(bytes) / Math.log(K));
            char pre = "KMGTPE".charAt(exp - 1);
            return String.format("%.1f %cB", bytes / Math.pow(K, exp), pre);
        }
    }

    private class MyDateRenderer
            extends DefaultTableCellRenderer {
        //        private final SimpleDateFormat sdf = new SimpleDateFormat("HH:mm dd/MM/yyyy");
        private final SimpleDateFormat sdf = new SimpleDateFormat("H:mm d/M/y");

        public MyDateRenderer() {
            setHorizontalAlignment(SwingConstants.RIGHT);
        }

        @Override
        public void setValue(Object value) {
            try {
                Date date = (Date) value;
                super.setValue(sdf.format(date));
            } catch (Exception e) {
                super.setValue(value);
            }
        }
    }
}

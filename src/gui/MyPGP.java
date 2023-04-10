package gui;

import bc.AlgorithmSelection;
import bc.BcUtilsClipboard;
import bc.KeySaver;
import bc.ToString;
import crypto.GetPassword;
import crypto.SecureDeleter;
import exception.MyLogger;
import exception.PasswordCancelled;
import gui.imgs.Icons;
import keys.*;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.bcpg.BCPGKey;
import org.bouncycastle.bcpg.ECDHPublicBCPGKey;
import org.bouncycastle.bcpg.ECDSAPublicBCPGKey;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;

import javax.swing.*;
import javax.swing.plaf.basic.BasicArrowButton;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreePath;
import java.awt.*;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.dnd.DnDConstants;
import java.awt.dnd.DropTarget;
import java.awt.dnd.DropTargetDropEvent;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.io.*;
import java.security.SecureRandom;
import java.security.Security;
import java.util.List;
import java.util.*;
import java.util.prefs.Preferences;

/**
 * @author Jose A. Manas
 * @version 30.12.2016
 */
public class MyPGP {
    private static final DataFlavor FILE_LIST_FLAVOR = DataFlavor.javaFileListFlavor;

    private static MyDirectoryChooser keyFileChooser;
    private static Directory directory;
    private static JButton processButton;
    private static JButton encryptButton;

    private static JFrame frame;
    private static final SecureRandom random = new SecureRandom();

    private static DefaultMutableTreeNode secKeyBranch;
    private static DefaultMutableTreeNode listsBranch;
    private static DefaultMutableTreeNode pubKeyBranch;

    private static JTree keysTree;

    private static MyFileChooser fch;
    private static JScrollPane keysPanel;

//    private static NewDirectoryAction newDirectoryAction;
//    private static RefreshAction refreshAction;
//    private static SecureDeleteAction secureDeleteAction;

    private static final Set<Object> selection = new HashSet<>();

    static {
        LogWindow.log("java home: " + System.getProperty("java.home"));
        LogWindow.log("java version: " + System.getProperty("java.version"));
        LogWindow.log("BouncyCastle version: " +
                BouncyCastleProvider.class.getPackage().getImplementationVersion());
        LogWindow.log("HOME: " + Info.getHome());
        LogWindow.log();
    }

    public static void start() {
        Security.addProvider(new BouncyCastleProvider());
        try {
            frame = new JFrame(Version.VERSION);
            frame.setIconImage(Icons.getPgpImage());
            frame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);

            init();
            frame.setJMenuBar(getMenuBar());
            getPanel();

            GraphicsEnvironment graphicsEnvironment = GraphicsEnvironment.getLocalGraphicsEnvironment();
            Rectangle total = graphicsEnvironment.getMaximumWindowBounds();
            frame.setSize(total.width / 2, total.height / 2);

//            frame.setExtendedState(Frame.MAXIMIZED_BOTH);

            frame.setVisible(true);
        } catch (Exception e) {
            MyLogger.dump(e, Version.VERSION);
        }
    }

    private static void init() {
        directory = Directory.load(Info.getHome());
        LogWindow.log();
        Info.loadInfo();

        keysTree = new JTree(mkKeysTree(directory));
        keysTree.setCellRenderer(new MyTreeRenderer(selection));
        keysTree.addMouseListener(new MyMouseListener(keysTree, selection));
        keysTree.setDropTarget(new DropTarget() {
            public synchronized void drop(DropTargetDropEvent evt) {
                try {
                    Point point = evt.getLocation();
                    TreePath treePath = keysTree.getPathForLocation(point.x, point.y);
                    if (treePath == null) {
                        evt.rejectDrop();
                        return;
                    }

                    DefaultMutableTreeNode node = (DefaultMutableTreeNode) treePath.getLastPathComponent();
                    File dir = getDirectory(node);
                    if (dir == null) {
                        evt.rejectDrop();
                        return;
                    }
                    evt.acceptDrop(DnDConstants.ACTION_COPY);
                    Transferable transferable = evt.getTransferable();
                    if (transferable.isDataFlavorSupported(FILE_LIST_FLAVOR)) {
                        List<File> droppedFiles = (List<File>) transferable.getTransferData(FILE_LIST_FLAVOR);
                        for (File srcFile : droppedFiles)
                            copy(dir, srcFile);
                        reloadKeys();
                    }
                } catch (Exception ex) {
                    MyLogger.dump(ex, Text.get("drop"));
                }
            }
        });
    }

    private static void copy(File dir, File srcFile) {
        File dstFile = new File(dir, srcFile.getName());
        try (InputStream srcIS = new FileInputStream(srcFile);
             OutputStream dstOS = new FileOutputStream(dstFile)
        ) {
            byte[] buffer = new byte[4 * 1024];
            for (; ; ) {
                int n = srcIS.read(buffer);
                if (n < 0)
                    break;
                dstOS.write(buffer, 0, n);
            }
        } catch (IOException e) {
            MyLogger.dump(e, "copy");
        }
    }

    private static File getDirectory(DefaultMutableTreeNode node) {
        boolean publicbranch = false;
        for (DefaultMutableTreeNode n = node; n != null; n = (DefaultMutableTreeNode) n.getParent()) {
            Object object = n.getUserObject();
            if (object == pubKeyBranch) {
                publicbranch = true;
                break;
            }
            if (object == secKeyBranch)
                return null;
            if (object == listsBranch)
                return null;
        }
        if (!publicbranch)
            return null;
        for (DefaultMutableTreeNode n = node; n != null; n = (DefaultMutableTreeNode) n.getParent()) {
            try {
                Object object = n.getUserObject();
                if (object == pubKeyBranch)
                    return directory.getFile();
                Directory directory = (Directory) object;
                return directory.getFile();
            } catch (Exception ignored) {
            }
        }
        return null;
    }

    private static void reloadKeys() {
        selection.clear();
        boolean secKeysExpanded = keysTree.isExpanded(new TreePath(secKeyBranch.getPath()));
        boolean listsExpanded = keysTree.isExpanded(new TreePath(listsBranch.getPath()));
        boolean directoryExpanded = keysTree.isExpanded(new TreePath(pubKeyBranch.getPath()));

        Set<Directory> expandedSecretKeys = getExpandedDirectories(secKeyBranch);
        Set<Directory> expandedPublicKeys = getExpandedDirectories(pubKeyBranch);

        KeyDB2.reset();
        KeyListDB.clear();
        directory = Directory.load(Info.getHome());
        Info.loadInfo();

        keysTree = new JTree(mkKeysTree(directory));
        keysTree.setCellRenderer(new MyTreeRenderer(selection));
        keysTree.addMouseListener(new MyMouseListener(keysTree, selection));
//            expandAll(keysTree);
        frame.getContentPane().remove(keysPanel);
        keysPanel = new JScrollPane(keysTree);
        frame.getContentPane().add(keysPanel);
        if (secKeysExpanded)
            keysTree.expandPath(new TreePath(secKeyBranch.getPath()));
        if (listsExpanded)
            keysTree.expandPath(new TreePath(listsBranch.getPath()));
        if (directoryExpanded)
            keysTree.expandPath(new TreePath(pubKeyBranch.getPath()));

        expandKeyDirectories(expandedSecretKeys, secKeyBranch);
        expandKeyDirectories(expandedPublicKeys, pubKeyBranch);

        frame.revalidate();
    }

    private static Set<Directory> getExpandedDirectories(DefaultMutableTreeNode branch) {
        Set<Directory> directorySet = new HashSet<>();
        int nChild = branch.getChildCount();
        for (int ch = 0; ch < nChild; ch++) {
            DefaultMutableTreeNode child = (DefaultMutableTreeNode) branch.getChildAt(ch);
            readExpandedDirectories(directorySet, child);
        }
        return directorySet;
    }

    private static void readExpandedDirectories(Set<Directory> directories, DefaultMutableTreeNode node) {
        Object object = node.getUserObject();
        if (!(object instanceof Directory))
            return;
        if (keysTree.isExpanded(new TreePath(node.getPath()))) {
            directories.add((Directory) object);
            for (int i = 0; i < node.getChildCount(); i++) {
                DefaultMutableTreeNode child = (DefaultMutableTreeNode) node.getChildAt(i);
                readExpandedDirectories(directories, child);
            }
        }
    }

    private static void expandKeyDirectories(Set<Directory> expandedKeys, DefaultMutableTreeNode branch) {
        int nChild = branch.getChildCount();
        for (int ch = 0; ch < nChild; ch++) {
            DefaultMutableTreeNode child = (DefaultMutableTreeNode) branch.getChildAt(ch);
            expandDirectories(expandedKeys, child);
        }
    }

    private static void expandDirectories(Set<Directory> directories, DefaultMutableTreeNode node) {
        Object object = node.getUserObject();
        if (!(object instanceof Directory))
            return;
        Directory directory = (Directory) object;
        if (!directories.contains(directory))
            return;
        keysTree.expandPath(new TreePath(node.getPath()));
        for (int i = 0; i < node.getChildCount(); i++) {
            DefaultMutableTreeNode child = (DefaultMutableTreeNode) node.getChildAt(i);
            expandDirectories(directories, child);
        }
    }

    private static DefaultMutableTreeNode mkKeysTree(Directory directory) {
        DefaultMutableTreeNode keysTreeRoot = new DefaultMutableTreeNode(Text.get("keys"));

        secKeyBranch = new DefaultMutableTreeNode(Text.get("secret_keys"));
        keysTreeRoot.add(secKeyBranch);
        mkKeyTree(secKeyBranch, directory, false);

        listsBranch = new DefaultMutableTreeNode(Text.get("lists"));
        keysTreeRoot.add(listsBranch);
        for (KeyList list : KeyListDB.getListSet())
            listsBranch.add(mkTreeList(list));

//        pubKeyBranch = new DefaultMutableTreeNode(directory.toString());
        pubKeyBranch = new DefaultMutableTreeNode(Text.get("public_keys"));
        keysTreeRoot.add(pubKeyBranch);
        mkKeyTree(pubKeyBranch, directory, true);

        return keysTreeRoot;
    }

    private static DefaultMutableTreeNode mkTreeList(KeyList list) {
        DefaultMutableTreeNode node = new DefaultMutableTreeNode(list);
        for (Key key : list.getMembers(true))
            node.add(mkTreeKey(key));
        return node;
    }

    private static void mkKeyTree(
            DefaultMutableTreeNode root, Directory directory, boolean pub) {
        for (Key key : directory.getKeys()) {
            if (pub || key.isSecret())
                root.add(mkTreeKey(key));
        }
        for (Directory sub : directory.getSubdirs()) {
            DefaultMutableTreeNode newChild = mkKeyTree(sub, pub);
            if (newChild.getChildCount() > 0)
                root.add(newChild);
        }
    }

    private static DefaultMutableTreeNode mkKeyTree(
            Directory directory, boolean pub) {
        DefaultMutableTreeNode node = new DefaultMutableTreeNode(directory);
        for (Key key : directory.getKeys()) {
            if (pub | key.isSecret())
                node.add(mkTreeKey(key));
        }
        for (Directory sub : directory.getSubdirs()) {
            DefaultMutableTreeNode newChild = mkKeyTree(sub, pub);
            if (newChild.getChildCount() > 0)
                node.add(newChild);
        }
        return node;
    }

    private static DefaultMutableTreeNode mkTreeKey(Key key) {
        return mkTreeKey(key, new HashSet<Long>());
    }

    /**
     * Builds a tree for a key.
     * Signers are nested.
     *
     * @param key       key to display.
     * @param hierarchy keys already in the chain to avoid endless loops of mutual certifications.
     * @return tree structure for this key, and signing keys.
     */
    private static DefaultMutableTreeNode mkTreeKey(Key key, Set<Long> hierarchy) {
        DefaultMutableTreeNode keyNode = new DefaultMutableTreeNode(key);
        keyNode.add(new DefaultMutableTreeNode(key.getCorePresentation()));
        DefaultMutableTreeNode detailNode = new DefaultMutableTreeNode(key.getIdFingerprint());
        keyNode.add(detailNode);
        PGPPublicKey publicKey = key.getMasterKey();
        PGPPublicKey encryptingKey = key.getEncryptingKey();
        StringBuilder builder = new StringBuilder();
        builder.append(ToString.publicKey(publicKey.getAlgorithm()))
                .append(" (").append(getBits(publicKey)).append(")");
        if (encryptingKey != null)
            builder.append(" / ")
                    .append(ToString.publicKey(encryptingKey.getAlgorithm()))
                    .append(" (").append(getBits(encryptingKey)).append(")");
        detailNode.add(new DefaultMutableTreeNode(builder.toString()));

        detailNode.add(mkEncryptionAlgorithms(publicKey));

        for (File file : key.getFileList())
            keyNode.add(new DefaultMutableTreeNode(fromHome(file)));

        List<Long> signerList = key.getSigIds();
        if (signerList.size() > 0) {
            Set<Long> extHierarchy = new HashSet<>(hierarchy);
            extHierarchy.addAll(signerList);
            DefaultMutableTreeNode signers = new DefaultMutableTreeNode(Text.get("signers") + " ...");
            keyNode.add(signers);
            for (Long sid : signerList) {
                Key signerKey = KeyDB2.getKey(sid);
                if (signerKey == null)
                    signers.add(new DefaultMutableTreeNode(String.format("[%s]", Key.mkId8(sid))));
                else if (hierarchy.contains(sid))
                    signers.add(new DefaultMutableTreeNode(String.format("[%s] %s", Key.mkId8(sid), signerKey)));
                else
                    signers.add(mkTreeKey(signerKey, extHierarchy));
            }
        }
        return keyNode;
    }

    private static String fromHome(File file) {
        try {
            String path = file.getCanonicalPath();
            String homePath = Info.getHome().getCanonicalPath();
            if (path.startsWith(homePath))
                return path.substring(homePath.length() + 1);
            return path;
        } catch (IOException e) {
            return file.getAbsolutePath();
        }
    }

    private static DefaultMutableTreeNode mkEncryptionAlgorithms(PGPPublicKey publicKey) {
        // encryption algorithms
        int[] algos = AlgorithmSelection.getPreferredEncryptionAlgos(publicKey);
        if (algos.length <= 0)
            return null;
        StringBuilder sb = new StringBuilder(Text.get("encrypt"));
        for (int i = 0; i < algos.length; i++) {
            if (i == 0)
                sb.append(": ");
            else
                sb.append(", ");
            sb.append(ToString.symmetricKey(algos[i]));
        }
        return new DefaultMutableTreeNode(sb.toString());
    }

    private static int getBits(PGPPublicKey publicKey) {
        int bitStrength = publicKey.getBitStrength();
        if (bitStrength > 0)
            return bitStrength;
        PublicKeyPacket packet = publicKey.getPublicKeyPacket();
        BCPGKey key = packet.getKey();

        X9ECParameters parameters = getECParameters(key);
        if (parameters != null) {
            ECCurve curve = parameters.getCurve();
            return curve.getFieldSize();
        }
        return 0;
    }

    private static X9ECParameters getECParameters(BCPGKey key) {
        ASN1ObjectIdentifier curveOID = null;
        if (key instanceof ECDSAPublicBCPGKey) {
            ECDSAPublicBCPGKey ecKey = (ECDSAPublicBCPGKey) key;
            curveOID = ecKey.getCurveOID();
        }
        if (key instanceof ECDHPublicBCPGKey) {
            ECDHPublicBCPGKey ecKey = (ECDHPublicBCPGKey) key;
            curveOID = ecKey.getCurveOID();
        }
        if (curveOID == null)
            return null;
        X9ECParameters parameters;
        parameters = NISTNamedCurves.getByOID(curveOID);
        if (parameters != null)
            return parameters;
        parameters = SECNamedCurves.getByOID(curveOID);
        if (parameters != null)
            return parameters;
        parameters = CustomNamedCurves.getByOID(curveOID);
        return parameters;
    }

    public static void getPanel() {
        final JTextField searchTextField = new JTextField();
//        searchTextField.setBorder(javax.swing.BorderFactory.createEmptyBorder());
        searchTextField.setColumns(20);
        searchTextField.setMaximumSize(searchTextField.getPreferredSize());
        searchTextField.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                find(true, searchTextField.getText());
            }
        });
        searchTextField.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent event) {
                if (event.getKeyCode() == KeyEvent.VK_DOWN)
                    find(true, searchTextField.getText());
                if (event.getKeyCode() == KeyEvent.VK_UP)
                    find(false, searchTextField.getText());
                SwingUtilities.invokeLater(new Runnable() {
                    @Override
                    public void run() {
                        searchTextField.requestFocusInWindow();
                    }
                });
            }
        });
        JButton upButton = new BasicArrowButton(SwingConstants.NORTH);
        upButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                find(false, searchTextField.getText());
            }
        });
        JButton downButton = new BasicArrowButton(SwingConstants.SOUTH);
        downButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent event) {
                find(true, searchTextField.getText());
            }
        });
        JPanel small = new JPanel();
        small.add(upButton);
        small.add(downButton);
        small.setMaximumSize(small.getPreferredSize());
        small.setBackground(new Color(0, 0, 0, 0));

        processButton = new JButton(Text.get("decrypt_verify"));
        encryptButton = new JButton(Text.get("encrypt_sign"));
        JToolBar buttons = new JToolBar();
        buttons.setFloatable(false);
        buttons.add(searchTextField);
        buttons.add(small);
        buttons.add(Box.createHorizontalGlue());
        buttons.add(encryptButton);
        buttons.add(Box.createHorizontalStrut(10));
        buttons.add(processButton);
        buttons.add(Box.createHorizontalGlue());

        processButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent event) {
                getFileChooser();
                File[] files = fch.getSelectedFiles();
                if (files == null || files.length == 0)
                    return;
                LogWindow.add(Text.get("decrypt_verify"));
                decrypt_verify_Selection(files);
            }
        });
        encryptButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent event) {
                getFileChooser();
                File[] files = fch.getSelectedFiles();
                if (files == null || files.length == 0)
                    return;
                LogWindow.add(Text.get("encrypt_sign"));
                encrypt_sign_Selection(files);
            }
        });

        processButton.setDropTarget(new DropTarget() {
            public synchronized void drop(DropTargetDropEvent evt) {
                try {
                    evt.acceptDrop(DnDConstants.ACTION_COPY);
                    Transferable transferable = evt.getTransferable();
                    if (transferable.isDataFlavorSupported(FILE_LIST_FLAVOR)) {
                        List<File> droppedFiles = (List<File>) transferable.getTransferData(FILE_LIST_FLAVOR);
                        LogWindow.add(Text.get("decrypt_verify"));
                        decrypt_verify_Selection(droppedFiles.toArray(new File[0]));
                    }
                } catch (Exception ex) {
                    MyLogger.dump(ex, Text.get("drop"));
                }
            }
        });
        encryptButton.setDropTarget(new DropTarget() {
            public synchronized void drop(DropTargetDropEvent evt) {
                try {
                    evt.acceptDrop(DnDConstants.ACTION_COPY);
                    Transferable transferable = evt.getTransferable();
                    if (transferable.isDataFlavorSupported(FILE_LIST_FLAVOR)) {
                        List<File> droppedFiles = (List<File>) transferable.getTransferData(FILE_LIST_FLAVOR);
                        LogWindow.add(Text.get("encrypt_sign"));
                        encrypt_sign_Selection(droppedFiles.toArray(new File[0]));
                    }
                } catch (Exception ex) {
                    MyLogger.dump(ex, Text.get("drop"));
                }
            }
        });

        keysPanel = new JScrollPane(keysTree);
        frame.getContentPane().add(keysPanel);
        frame.getContentPane().add(buttons, BorderLayout.SOUTH);
    }

    private static DefaultMutableTreeNode last;

    private static void find(boolean goDown, String text) {
        if (text == null || text.length() == 0)
            return;
        DefaultMutableTreeNode root = (DefaultMutableTreeNode) keysTree.getModel().getRoot();
        DefaultMutableTreeNode from;
        int row = keysTree.getMinSelectionRow();
        if (row < 0) {
            from = last;
        } else {
            TreePath path = keysTree.getPathForRow(row);
            from = (DefaultMutableTreeNode) path.getLastPathComponent();
        }
        if (from == null)
            from = root;
        if (from == null)
            return;
        DefaultMutableTreeNode found = find(goDown, text.toLowerCase(), from);
        if (found != null) {
            last = found;
            TreePath path = new TreePath(found.getPath());
            keysTree.makeVisible(path);
            keysTree.setSelectionPath(path);
            keysTree.scrollPathToVisible(path);
        }
    }

    private static DefaultMutableTreeNode find(boolean goDown, String text, DefaultMutableTreeNode from) {
        DefaultMutableTreeNode root = (DefaultMutableTreeNode) keysTree.getModel().getRoot();
        DefaultMutableTreeNode tail = root.getLastLeaf();
        boolean root_visited = false;
        DefaultMutableTreeNode next = from;
        try {
            for (; ; ) {
                if (goDown)
                    next = next.getNextNode();
                else
                    next = next.getPreviousNode();
                if (next == null) {
                    if (root_visited)
                        return null;
                    if (goDown)
                        next = root;
                    else
                        next = tail;
                    root_visited = true;
                }
                if (next == from)
                    return null;
                Object object = next.getUserObject();
                if (object instanceof Key) {
                    String name = object.toString();
                    if (name != null && name.length() > 0 &&
                            name.toLowerCase().contains(text))
                        return next;
                }
            }
        } catch (Exception e) {
            return null;
        }
    }

    private static int getFileChooser() {
        if (fch == null) {
            Preferences preferences = Preferences.userRoot().node("mypgp");
            fch = new MyFileChooser();
            fch.setPreferences(preferences);
            String wd = preferences.get("working_dir", null);
            if (wd != null) {
                File wdFile = new File(wd);
                if (wdFile.exists() && wdFile.isDirectory())
                    fch.setDirectory(wdFile);
            }
        }
        fch.rescanCurrentDirectory();
        return JOptionPane.showConfirmDialog(null,
                fch, Version.VERSION,
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE,
                Icons.getPgpIcon());
    }

    private static void decrypt_verify_Selection(File[] files) {
        String action = Text.get("decrypt_verify");
        DecryptVerifyWorker worker = new DecryptVerifyWorker(action, files);
        worker.execute();
    }

    private static void encrypt_sign_Selection(File[] files) {
        String action = Text.get("encrypt_sign");
        List<Key> encryptingKeys = getPublicKeys();
        List<Key> signingKeys = getSecretKeys();
        if (encryptingKeys.size() + signingKeys.size() == 0)
            return;

        Map<Key, char[]> passwords = new HashMap<>();
        if (signingKeys.size() > 0) {
            try {
                for (Key signingKey : signingKeys) {
                    String label = Text.get("sign") + ": " + signingKey;
                    char[] password = GetPassword.getInstance().getDecryptionPassword(label);
                    passwords.put(signingKey, password);
                }
            } catch (PasswordCancelled passwordCancelled) {
                return;
            }
        }

        try {
            String alt = ".pgp";
            if (encryptingKeys.size() > 0 && signingKeys.size() > 0)
                alt = ".pgp, .sig";
            if (encryptingKeys.size() > 0 && signingKeys.size() == 0)
                alt = ".pgp";
            if (encryptingKeys.size() == 0 && signingKeys.size() > 0)
                alt = ".sig";
            if (encryptingKeys.size() == 0 && signingKeys.size() == 0)
                alt = "";
            boolean armor = ArmorPanel.getArmor(action, true, alt);  // mark 30.1.2023
            EncryptSignWorker worker = new EncryptSignWorker(action, files, encryptingKeys, signingKeys, passwords, armor);
            worker.execute();
        } catch (PasswordCancelled ignored) {
        }
    }

    private static JMenuBar getMenuBar() {
        JMenuBar menuBar = new JMenuBar();
        JMenu keyMenu = new JMenu(Text.get("keys"));
        menuBar.add(keyMenu);
        keyMenu.add(new GenerateKeyAction());
        keyMenu.add(new AliasKeyAction(true));
        keyMenu.add(new CopyKeyAction(true));
        keyMenu.add(new ExportKeyAction(true));
        keyMenu.add(new ReloadKeysAction());
        keyMenu.add(new FileMapAction());
        keyMenu.add(new SplitAction());

        JMenu listsMenu = new JMenu(Text.get("lists"));
        menuBar.add(listsMenu);
        listsMenu.add(new AddKeyListAction(true));
        listsMenu.add(new RemoveKeyListAction(true));
        listsMenu.add(new NewListAction());
        listsMenu.add(new RemoveListAction(true));

        JMenu clipMenu = new JMenu(Text.get("clipboard"));
        menuBar.add(clipMenu);
        clipMenu.add(new ViewClipAction());
        clipMenu.add(new EncryptClipAction());
        clipMenu.add(new SignClipAction());
        clipMenu.add(new EncryptSignClipAction());
        clipMenu.add(new DecryptClipAction());

        JMenu fileMenu = new JMenu(Text.get("files"));
        menuBar.add(fileMenu);
        fileMenu.add(new EncryptAction());
        fileMenu.add(new SignAction());
        fileMenu.add(new EncryptSignAction());
        fileMenu.add(new DecryptAction());
        fileMenu.add(new SecureDeleteAction());

        JMenu langMenu = new JMenu(Text.get("language"));
        menuBar.add(langMenu);
        for (final String[] pair : Text.getLanguages()) {
            JMenuItem item = new JMenuItem(pair[1]);
            item.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    Text.setLocale(pair[0]);
                    Info.saveLanguage();
                    reloadKeys();
//                    newDirectoryAction.putValue(Action.NAME, Text.get("new_directory"));
//                    refreshAction.putValue(Action.NAME, Text.get("refresh"));
//                    secureDeleteAction.putValue(Action.NAME, Text.get("delete"));
                    processButton.setText(Text.get("decrypt_verify"));
                    encryptButton.setText(Text.get("encrypt_sign"));
                    frame.setJMenuBar(getMenuBar());
                    frame.validate();
                }
            });
            langMenu.add(item);
        }

        return menuBar;
    }

    private static List<Key> getSecretKeys(boolean checked) {
        List<Key> keys = new ArrayList<>();
        Collection<TreePath> paths = getSelectionPaths(checked);
        if (paths.isEmpty())
            return keys;

        for (TreePath path : paths) {
            if (path.getPathComponent(1) != secKeyBranch)
                continue;
            DefaultMutableTreeNode node = (DefaultMutableTreeNode) path.getLastPathComponent();
            Object object = node.getUserObject();
            if (object.getClass() == Key.class)
                keys.add((Key) object);
        }
        return keys;
    }

    private static Collection<TreePath> getSelectionPaths(boolean checked) {
        if (!checked)
            return Arrays.asList(keysTree.getSelectionPaths());

        Collection<TreePath> all = new HashSet<>();
        for (Object x : selection) {
            DefaultMutableTreeNode node = (DefaultMutableTreeNode) x;
            if (selection.contains(node)) {
                TreePath path = new TreePath(node.getPath());
                all.add(path);
            }
        }
        return all;
    }

    private static List<Key> getSecretKeys() {
        List<Key> keys = new ArrayList<>();
        for (Key key : getSecretKeys(true)) {
            if (key.getSigningKey() != null)
                keys.add(key);
        }
        for (Key key : keys)
            LogWindow.signer(key);
        return keys;
    }

    private static List<Key> getPublicKeys(boolean checked) {
        List<Key> keys = new ArrayList<>();
        Collection<TreePath> paths = getSelectionPaths(checked);
        if (paths.isEmpty())
            return keys;

        for (TreePath path : paths) {
            if (path.getPathComponent(1) == secKeyBranch)
                continue;
            DefaultMutableTreeNode node = (DefaultMutableTreeNode) path.getLastPathComponent();
            Object object = node.getUserObject();
            if (object.getClass() == Key.class) {
                keys.add((Key) object);
            } else if (object.getClass() == KeyList.class) {
                KeyList list = (KeyList) object;
                keys.addAll(list.getMembers(false));

            } else if (object.getClass() == Directory.class) {
                Directory directory = (Directory) object;
                directory.addKeys(keys);

            }
        }
        return keys;
    }

    private static List<KeyList> getKeyLists(boolean checked) {
        List<KeyList> keyLists = new ArrayList<>();
        Collection<TreePath> paths = getSelectionPaths(checked);
        if (paths.isEmpty())
            return keyLists;

        for (TreePath path : paths) {
            try {
                if (path.getPathComponent(1) != listsBranch)
                    continue;
                DefaultMutableTreeNode node = (DefaultMutableTreeNode) path.getLastPathComponent();
                keyLists.add((KeyList) node.getUserObject());
            } catch (Exception ignored) {
            }
        }
        return keyLists;
    }

    private static List<Key> getPublicKeys() {
        List<Key> keyList = new ArrayList<>();
        for (Key key : getPublicKeys(true)) {
            PGPPublicKey encryptingKey = key.getEncryptingKey();
            if (encryptingKey != null)
                keyList.add(key);
        }
        for (Key key : keyList)
            LogWindow.encryptingFor(key);
        return keyList;
    }

    private static List<DefaultMutableTreeNode> getLists(boolean checked) {
        List<DefaultMutableTreeNode> lists = new ArrayList<>();
        Collection<TreePath> paths = getSelectionPaths(checked);
        if (paths.isEmpty())
            return lists;

        for (TreePath path : paths) {
            DefaultMutableTreeNode node = (DefaultMutableTreeNode) path.getLastPathComponent();
            Object object = node.getUserObject();
            if (object.getClass() == KeyList.class)
                lists.add(node);
        }
        return lists;
    }

    static Window getWindow() {
        return frame;
    }

    public static void ignore(String absolutePath) {
        if (absolutePath.toLowerCase().endsWith(".jar"))
            return;
        LogWindow.log(Text.get("skip") + " " + absolutePath);
    }

    static DefaultMutableTreeNode getSecKeyBranch() {
        return secKeyBranch;
    }

    private static class EncryptAction
            extends AbstractAction {
        private EncryptAction() {
            super(Text.get("encrypt"));
        }

        public void actionPerformed(ActionEvent event) {
            getFileChooser();
            File[] files = fch.getSelectedFiles();
            if (files == null || files.length == 0)
                return;
            LogWindow.add(Text.get("encrypt"));
            encrypt_sign_Selection(files);
        }
    }

    private static class SignAction
            extends AbstractAction {
        private SignAction() {
            super(Text.get("sign"));
        }

        public void actionPerformed(ActionEvent event) {
            String action = Text.get("sign");
            getFileChooser();
            File[] files = fch.getSelectedFiles();
            if (files == null || files.length == 0)
                return;

            Map<Key, char[]> passwords = new HashMap<>();
            LogWindow.add(Text.get("sign"));
            List<Key> signingKeys = getSecretKeys();
            if (signingKeys.isEmpty()) {
                LogWindow.add(String.format("%s: %d%n", Text.get("secret_keys"), signingKeys.size()));
                return;
            }

            boolean armor;
            try {
                armor = ArmorPanel.getArmor(action, false, ".sig");
                for (Key signingKey : signingKeys) {
                    String label = action + ": " + signingKey;
                    char[] password = GetPassword.getInstance().getDecryptionPassword(label);
                    passwords.put(signingKey, password);
                }
            } catch (PasswordCancelled passwordCancelled) {
                return;
            }

            SignWorker worker = new SignWorker(action, files, signingKeys, passwords, armor);
            worker.execute();
        }
    }

    private static class EncryptSignAction
            extends AbstractAction {
        private EncryptSignAction() {
            super(Text.get("encrypt_sign"));
        }

        public void actionPerformed(ActionEvent event) {
            getFileChooser();
            File[] files = fch.getSelectedFiles();
            if (files == null || files.length == 0)
                return;

            LogWindow.add(Text.get("encrypt_sign"));
            encrypt_sign_Selection(files);
        }
    }

    private static class DecryptAction
            extends AbstractAction {
        private DecryptAction() {
            super(Text.get("decrypt_verify"));
        }

        public void actionPerformed(ActionEvent event) {
            getFileChooser();
            File[] files = fch.getSelectedFiles();
            if (files == null || files.length == 0)
                return;

            LogWindow.add(Text.get("decrypt_verify"));
            decrypt_verify_Selection(files);
        }
    }

    private static class ViewClipAction
            extends AbstractAction {
        private ViewClipAction() {
            super(Text.get("view"));
        }

        public void actionPerformed(ActionEvent event) {
            try {
                String text = MyClipBoard.readString();
                JTextArea area = new JTextArea(text, 40, 80);
                area.setWrapStyleWord(true);
                area.setLineWrap(true);
                JScrollPane pane = new JScrollPane(area);
                JDialog dialog = new JDialog((Window) null, Text.get("clipboard"));
                dialog.add(pane);
                dialog.pack();
                dialog.setVisible(true);
            } catch (Exception e) {
                MyLogger.dump(e, Text.get("view"));
            }
        }
    }

    private static class EncryptClipAction
            extends AbstractAction {
        private EncryptClipAction() {
            super(Text.get("encrypt"));
        }

        public void actionPerformed(ActionEvent event) {
            String action = Text.get("encrypt");

            List<Key> keyList = getPublicKeys();
            if (keyList.size() == 0) {
                LogWindow.log(String.format("%s: 0%n", Text.get("public_keys")));
                return;
            }

            LogWindow.add(action + " " + Text.get("clipboard"));
            try {
                String redText = MyClipBoard.readString();
                String blackText = BcUtilsClipboard.encrypt(redText, keyList);
                MyClipBoard.write(blackText);
            } catch (PGPException e) {
                LogWindow.add(e);
                if (e.getUnderlyingException() != null)
                    MyLogger.dump(e.getUnderlyingException(), action);
            } catch (Exception e) {
                MyLogger.dump(e, action);
            }
        }
    }

    private static class SignClipAction
            extends AbstractAction {
        private SignClipAction() {
            super(Text.get("sign"));
        }

        public void actionPerformed(ActionEvent event) {
            String action = Text.get("sign");

            LogWindow.add(action + " " + Text.get("clipboard"));
            List<Key> keyList = getSecretKeys();
            if (keyList.size() != 1) {
                LogWindow.add(String.format("%s: %d%n", Text.get("secret_keys"), keyList.size()));
                return;
            }
            Key signingKey = keyList.get(0);
            try {
                String redText = MyClipBoard.readString();
                String label = action + ": " + signingKey;
                char[] password = GetPassword.getInstance().getDecryptionPassword(label);
                String blackText = BcUtilsClipboard.clearsign(redText, signingKey, password);
                MyClipBoard.write(blackText);
            } catch (PasswordCancelled ignored) {
            } catch (PGPException e) {
                LogWindow.add(e);
                if (e.getUnderlyingException() != null)
                    MyLogger.dump(e.getUnderlyingException(), action);
            } catch (Exception e) {
                MyLogger.dump(e, action);
            }
        }
    }

    private static class EncryptSignClipAction
            extends AbstractAction {
        private EncryptSignClipAction() {
            super(Text.get("encrypt_sign"));
        }

        public void actionPerformed(ActionEvent event) {
            encrypt_sign_Clipboard(MyClipBoard.readString());
        }
    }

    private static void encrypt_sign_Clipboard(String redText) {
        String action = Text.get("encrypt_sign");

        char[] password = new char[0];
        try {
            LogWindow.add(action);
            LogWindow.add(Text.get("clipboard"));
            List<Key> encryptingKeys = getPublicKeys();
            List<Key> signingKeys = getSecretKeys();
            if (encryptingKeys.size() + signingKeys.size() == 0)
                return;

            PGPSecretKey signingKey = null;
            if (signingKeys.size() > 0) {
                try {
                    signingKey = signingKeys.get(0).getSigningKey();
                    String label = Text.get("sign") + ": " + signingKey;
                    password = GetPassword.getInstance().getDecryptionPassword(label);
                } catch (PasswordCancelled passwordCancelled) {
                    return;
                }
            }
            if (signingKey == null)
                return;

            try {
                String blackText = "";
                if (encryptingKeys.size() > 0 && signingKeys.size() > 0)
                    blackText = BcUtilsClipboard.encrypt_sign(redText, encryptingKeys, signingKey, password);
                if (encryptingKeys.size() > 0 && signingKeys.size() == 0)
                    blackText = BcUtilsClipboard.encrypt(redText, encryptingKeys);
                if (encryptingKeys.size() == 0 && signingKeys.size() > 0)
                    blackText = BcUtilsClipboard.sign(redText, signingKey, password);
                MyClipBoard.write(blackText);
            } catch (PGPException e) {
                LogWindow.add(e);
                if (e.getUnderlyingException() != null)
                    MyLogger.dump(e.getUnderlyingException(), action);
            } catch (Exception e) {
                MyLogger.dump(e, action);
            }
        } finally {
            clearPassword(password);
        }
    }

    private static class DecryptClipAction
            extends AbstractAction {
        private DecryptClipAction() {
            super(Text.get("decrypt_verify"));
        }

        public void actionPerformed(ActionEvent event) {
            String action = Text.get("decrypt_verify");
            LogWindow.add(action + " " + Text.get("clipboard"));
            try {
                String blackText = MyClipBoard.readString();
                String redText = BcUtilsClipboard.process(blackText);
                MyClipBoard.write(redText);
            } catch (PasswordCancelled ignored) {
            } catch (PGPException e) {
                LogWindow.add(e);
                if (e.getUnderlyingException() != null)
                    MyLogger.dump(e.getUnderlyingException(), action);
            } catch (Exception e) {
                MyLogger.dump(e, action);
            }
        }
    }

    private static class SecureDeleteAction
            extends AbstractAction {
        private SecureDeleteAction() {
            super(Text.get("delete"));
        }

        public void actionPerformed(ActionEvent event) {
            String action = Text.get("delete");
            LogWindow.add(action);
            getFileChooser();
            File[] files = fch.getSelectedFiles();
            if (files == null || files.length == 0)
                return;

            for (File file : files) {
                try {
                    String msg = String.format(
                            "<html><b>%s</b>:<br>%s</html>",
                            file.getName(), Text.get("delete?")
                    );
                    int result = JOptionPane.showConfirmDialog(null,
                            msg,
                            action,
                            JOptionPane.OK_CANCEL_OPTION,
                            JOptionPane.QUESTION_MESSAGE,
                            Icons.getPgpIcon());
                    if (result != JOptionPane.OK_OPTION)
                        return;
                    LogWindow.add(file.getName());
                    SecureDeleter.delete(file);
                } catch (Exception e) {
                    MyLogger.dump(e, action);
                }
            }
        }
    }

    static void fileDeleted(SecureDeleteWorker worker) {
        try {
            Exception executonException = worker.getExecutonException();
            if (executonException != null)
                throw executonException;
        } catch (Exception e) {
            MyLogger.dump(e, Text.get("delete"));
        }
    }

    private static class GenerateKeyAction
            extends AbstractAction {
        private GenerateKeyAction() {
            super(Text.get("generate"));
        }

        public void actionPerformed(ActionEvent event) {
            MyDirectoryChooser directoryChooser = new MyDirectoryChooser();
            directoryChooser.setDirectory(Info.getHome());
            Object[] options = {Text.get("accept"), Text.get("cancel")};
            int ret = JOptionPane.showOptionDialog(null,
                    directoryChooser,
                    Text.get("key_directory"),
                    JOptionPane.DEFAULT_OPTION,
                    JOptionPane.PLAIN_MESSAGE,
                    Icons.getPgpIcon(),
                    options, options[0]);
            if (ret != JFileChooser.APPROVE_OPTION)
                return;
            File where = directoryChooser.getSelectedDirectory();

            final KeyGenPanel panel = new KeyGenPanel();
            for (; ; ) {
                int result = JOptionPane.showConfirmDialog(null,
                        panel, Text.get("generate"),
                        JOptionPane.OK_CANCEL_OPTION,
                        JOptionPane.QUESTION_MESSAGE,
                        Icons.getPgpIcon());
                if (result != JOptionPane.OK_OPTION)
                    return;
                if (panel.getName().length() == 0)
                    continue;
                if (panel.getEmail().length() == 0)
                    continue;
                if (panel.getExpireDate() == null)
                    continue;
                char[] password = panel.getPassword();
                if (password == null || password.length == 0)
                    continue;
                break;
            }
            LogWindow.add(Text.get("generate"));

            KeyGeneratingThread task = new KeyGeneratingThread(
                    where,
                    panel.getSignAlgo(), panel.getEncryptAlgo(),
                    panel.getName(), panel.getEmail(), panel.getComment(),
                    panel.getExpireDate(),
                    panel.getPassword());
            KeyGeneratingWorker worker = new KeyGeneratingWorker(task);
            worker.execute();
        }
    }

    static void keyGenerated(KeyGeneratingThread task) {
        try {
            long delta = task.getDelta();
            LogWindow.add(String.format("%dm %ds", delta / 60, delta % 60));
            Exception executionException = task.getExecutionException();
            if (executionException != null)
                throw executionException;
            LogWindow.add(task.getResult());
        } catch (Exception e) {
            if (e instanceof PGPException) {
                PGPException pgpException = (PGPException) e;
                LogWindow.add(pgpException);
                if (pgpException.getUnderlyingException() != null)
                    MyLogger.dump(pgpException.getUnderlyingException(), Text.get("generate"));
            } else {
                MyLogger.dump(e, Text.get("generate"));
            }
        }
        reloadKeys();
    }

    static class AliasKeyAction
            extends AbstractAction {
        private final boolean checked;

        AliasKeyAction(boolean checked) {
            super(Text.get("alias"));
            this.checked = checked;
        }

        public void actionPerformed(ActionEvent event) {
            List<Key> secretKeys = getSecretKeys(checked);
            List<Key> publicKeys = getPublicKeys(checked);
            if (secretKeys.size() == 0 && publicKeys.size() == 0) {
                LogWindow.log(String.format("%s: 0%n", Text.get("public_keys")));
                LogWindow.log(String.format("%s: 0%n", Text.get("secret_keys")));
                return;
            }

            for (Key key : secretKeys)
                setAlias(key);
            for (Key key : publicKeys)
                setAlias(key);
            Info.saveInfo();
            reloadKeys();
        }

        private void setAlias(Key key) {
            JTextField aliasLabel = new JTextField(key.toString());
            int result = JOptionPane.showConfirmDialog(null,
                    aliasLabel, Text.get("alias"),
                    JOptionPane.OK_CANCEL_OPTION,
                    JOptionPane.QUESTION_MESSAGE,
                    Icons.getPgpIcon());
            if (result != JOptionPane.OK_OPTION)
                return;
            KeyDB2.setAlias(key.getKid(), aliasLabel.getText());
        }
    }

    static class CopyKeyAction
            extends AbstractAction {
        private final boolean checked;

        CopyKeyAction(boolean checked) {
            super(Text.get("copy"));
            this.checked = checked;
        }

        public void actionPerformed(ActionEvent event) {
            List<Key> secretKeys = getSecretKeys(checked);
            List<Key> publicKeys = getPublicKeys(checked);
            if (secretKeys.size() == 0 && publicKeys.size() == 0) {
                LogWindow.log(String.format("%s: 0%n", Text.get("public_keys")));
                LogWindow.log(String.format("%s: 0%n", Text.get("secret_keys")));
                return;
            }

            StringBuilder builder = new StringBuilder();
            for (Key key : secretKeys)
                copy(builder, key);
            for (Key key : publicKeys)
                copy(builder, key);
            MyClipBoard.write(builder.toString());
        }

        private void copy(StringBuilder builder, Key key) {
            builder.append(key.toString()).append('\n');
            builder.append(Text.get("fingerprint")).append(": ").append(key.getFingerprintHex4()).append('\n');
        }
    }

    static class ExportKeyAction
            extends AbstractAction {
        private final boolean checked;

        ExportKeyAction(boolean checked) {
            super(Text.get("export"));
            this.checked = checked;
        }

        public void actionPerformed(ActionEvent event) {
            List<Key> secretKeys = getSecretKeys(checked);
            List<Key> publicKeys = getPublicKeys(checked);
            if (secretKeys.size() == 0 && publicKeys.size() == 0) {
                LogWindow.log(String.format("%s: 0%n", Text.get("public_keys")));
                LogWindow.log(String.format("%s: 0%n", Text.get("secret_keys")));
                return;
            }
            File where = getFile();
            if (where == null)
                return;

            LogWindow.add(Text.get("export"));
            for (Key key : secretKeys) {
                LogWindow.secret(key);
                KeySaver.exportSecretKey(where, key);
            }
            for (Key key : publicKeys) {
                LogWindow.pub(key);
                KeySaver.exportPublicKey(where, key);
            }
        }

        private File getFile() {
            if (keyFileChooser == null) {
                keyFileChooser = new MyDirectoryChooser();
                keyFileChooser.setDirectory(Info.getHome());
            }
            Object[] options = {Text.get("accept"), Text.get("cancel")};
            int ret = JOptionPane.showOptionDialog(null,
                    keyFileChooser,
                    Text.get("select_directory"),
                    JOptionPane.DEFAULT_OPTION,
                    JOptionPane.PLAIN_MESSAGE,
                    Icons.getPgpIcon(),
                    options, options[0]);
            if (ret != JFileChooser.APPROVE_OPTION)
                return null;
            return keyFileChooser.getSelectedDirectory();
        }
    }

    private static class ReloadKeysAction
            extends AbstractAction {
        private ReloadKeysAction() {
            super(Text.get("refresh"));
        }

        public void actionPerformed(ActionEvent event) {
            reloadKeys();
        }
    }

    private static class FileMapAction
            extends AbstractAction {
        private FileMapAction() {
            super(String.format("%s & %s", Text.get("files"), Text.get("keys")));
        }

        public void actionPerformed(ActionEvent event) {
            StringBuilder builder = new StringBuilder();
            directory.dumpLog(builder);
            MyTextArea.show(builder.toString(), frame);
        }
    }

    private static class SplitAction
            extends AbstractAction {
        private SplitAction() {
            super(Text.get("split"));
        }

        public void actionPerformed(ActionEvent event) {
            getFileChooser();
            File file = fch.getSelectedFile();
            if (file == null)
                return;
            RingSplitter splitter = new RingSplitter(file);
            splitter.go();
        }
    }

    private static class AddKeyListAction
            extends AbstractAction {
        private final boolean checked;

        private AddKeyListAction(boolean checked) {
            super(Text.get("add_key_list"));
            this.checked = checked;
        }

        public void actionPerformed(ActionEvent event) {
            List<Key> publicKeys = getPublicKeys(checked);
            if (publicKeys.size() == 0) {
                LogWindow.log(String.format("%s: 0%n", Text.get("public_keys")));
                return;
            }

            List<DefaultMutableTreeNode> listNodes = getLists(checked);
            if (listNodes.size() == 0) {
                LogWindow.log(String.format("%s: 0%n", Text.get("lists")));
                return;
            }

            for (DefaultMutableTreeNode node : listNodes) {
                KeyList list = (KeyList) node.getUserObject();
                for (Key key : publicKeys)
                    list.add(key);
            }
            Info.saveInfo();
            reloadKeys();
        }
    }

    static class RemoveKeyListAction
            extends AbstractAction {
        private final boolean checked;

        RemoveKeyListAction(boolean checked) {
            super(Text.get("remove_key_list"));
            this.checked = checked;
        }

        public void actionPerformed(ActionEvent event) {
            Collection<TreePath> paths = getSelectionPaths(checked);
            if (paths.isEmpty())
                return;

            if (checked) {
                List<Key> secretKeys = getSecretKeys(true);
                List<Key> publicKeys = getPublicKeys(true);
                List<KeyList> keyLists = getKeyLists(true);
                for (KeyList keyList : keyLists) {
                    for (Key key : secretKeys)
                        keyList.remove(key);
                    for (Key key : publicKeys)
                        keyList.remove(key);
                }

            } else {
                for (TreePath path : paths) {
                    try {
                        DefaultMutableTreeNode node = (DefaultMutableTreeNode) path.getLastPathComponent();
                        Key key = (Key) node.getUserObject();
                        KeyList keyList = null;
                        for (DefaultMutableTreeNode n = node; n != null; n = (DefaultMutableTreeNode) n.getParent())
                            keyList = (KeyList) n.getUserObject();
                        keyList.remove(key);
                    } catch (Exception ignored) {
                    }
                }
            }

            for (int i = 0; i < listsBranch.getChildCount(); i++) {
                DefaultMutableTreeNode listNode = (DefaultMutableTreeNode) listsBranch.getChildAt(i);
                removeFrom(listNode);
            }

            Info.saveInfo();
            reloadKeys();
        }

        private void removeFrom(DefaultMutableTreeNode listNode) {
            KeyList list = (KeyList) listNode.getUserObject();
            for (int j = 0; j < listNode.getChildCount(); j++) {
                DefaultMutableTreeNode keyNode = (DefaultMutableTreeNode) listNode.getChildAt(j);
                TreePath keyPath = new TreePath(keyNode.getPath());
                if (keysTree.isPathSelected(keyPath)) {
                    Key key = (Key) keyNode.getUserObject();
                    list.remove(key);
                }
            }
        }
    }

    static class NewListAction
            extends AbstractAction {
        NewListAction() {
            super(Text.get("new_list"));
        }

        public void actionPerformed(ActionEvent event) {
            String label = Text.get("new_list");
            JTextField textField = new JTextField(20);
            int result = JOptionPane.showConfirmDialog(null,
                    textField, label,
                    JOptionPane.OK_CANCEL_OPTION,
                    JOptionPane.QUESTION_MESSAGE,
                    Icons.getPgpIcon());
            if (result != JOptionPane.OK_OPTION)
                return;
            String listname = textField.getText();
            if (listname == null || listname.length() == 0)
                return;
            if (KeyListDB.get(listname) != null)
                return;
            KeyList list = new KeyList(listname);
            KeyListDB.add(list);
            Info.saveInfo();
            reloadKeys();
        }
    }

    static class RemoveListAction
            extends AbstractAction {
        private final boolean checked;

        RemoveListAction(boolean checked) {
            super(Text.get("remove_list"));
            this.checked = checked;
        }

        public void actionPerformed(ActionEvent event) {
            List<DefaultMutableTreeNode> listNodes = getLists(checked);
            if (listNodes.size() == 0) {
                LogWindow.log(String.format("%s: 0%n%n", Text.get("lists")));
                return;
            }

            for (DefaultMutableTreeNode node : listNodes) {
                KeyList list = (KeyList) node.getUserObject();
                int result = JOptionPane.showConfirmDialog(null,
                        list.getName(),
                        Text.get("remove_list"),
                        JOptionPane.OK_CANCEL_OPTION,
                        JOptionPane.QUESTION_MESSAGE,
                        Icons.getPgpIcon());
                if (result != JOptionPane.OK_OPTION)
                    return;
                KeyListDB.removeList(list);
            }
            Info.saveInfo();
            reloadKeys();
        }
    }

    private static void clearPassword(char[] password) {
        for (int i = 0; i < password.length; i++)
            password[i] = (char) random.nextInt();
    }
}

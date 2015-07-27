package gui;

import bc.*;
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
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;

import javax.swing.*;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreePath;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileNotFoundException;
import java.util.*;
import java.util.List;
import java.util.prefs.Preferences;

// 22.5.2011 export multiple keys
// 22.5.2011 alias
// 1.6.2011 lists
// 8.6.2011 use file chooser to import keys
// 29.6.2011 add logs of void actions
// 29.6.2011 revise removal of keys from lists
// 19.7.2011 look for recipients before decrypting
// 2.9.2011 view clipboard
// 2.9.2011 process clipboard
// 29.10.2011 secure delete in right tool bar
// 23.11.2011 show key id
// 23.11.2011 show fingerprint
// 7.7.2012 KeyDB replaced for KeyDB2
// 23.6.2013 force cursor to end of log area after writing
// 21.8.2014 fully revised

/**
 * @author Jose A. Manas
 * @version 21.8.2014
 */
public class MyPGP {
    private static MyPGP instance;
    private MyDirectoryChooser keyFileChooser;
    private Directory directory;
    private JButton processButton;
    private JButton encryptButton;

    public static MyPGP getInstance() {
        if (instance == null)
            instance = new MyPGP();
        return instance;
    }

    private static JFrame frame;

    private DefaultMutableTreeNode secKeyBranch;
    private DefaultMutableTreeNode listsBranch;
    private DefaultMutableTreeNode directoryBranch;

    private final JTextArea logArea;
    private JTree keysTree;

    private MyFileChooser fch;
    private JPanel keysPanel;

    private NewDirectoryAction newDirectoryAction;
    private RefreshAction refreshAction;
    private SecureDeleteAction secureDeleteAction;

    private JPopupMenu popupKeyInRings;
    private JPopupMenu popupKeyInList;
    private JPopupMenu popupList;

    public static void start() {
        Provider.set();
        try {
            frame = new JFrame(Version.VERSION);
            frame.setIconImage(Icons.getPgpImage());
            frame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);

            getInstance().init();
            frame.setJMenuBar(instance.getMenuBar());
            frame.getContentPane().add(instance.getPanel());
            frame.pack();
            frame.setExtendedState(Frame.MAXIMIZED_BOTH);

            frame.setVisible(true);
        } catch (Exception e) {
            MyLogger.dump(e, Version.VERSION);
        }
    }

    private MyPGP() {
        logArea = new JTextArea(20, 80);
        logArea.setWrapStyleWord(true);
        logArea.setLineWrap(true);
        log("java home: " + System.getProperty("java.home"));
        log("java version: " + System.getProperty("java.version"));
        log("HOME: " + Info.getHome());
        log("");
    }

    private void init() {
        directory = Directory.load(Info.getHome());
        Info.loadInfo();
        log("");

        keysTree = new JTree(mkKeysTree(directory));
        keysTree.setCellRenderer(new MyTreeRenderer());
        keysTree.addMouseListener(new MyMouseListener());
//        expandAll(keysTree);
    }

    private void reloadKeys() {
        boolean secKeysExpanded = keysTree.isExpanded(new TreePath(secKeyBranch.getPath()));
        boolean listsExpanded = keysTree.isExpanded(new TreePath(listsBranch.getPath()));
        boolean directoryExpanded = keysTree.isExpanded(new TreePath(directoryBranch.getPath()));

        KeyDB2.getInstance().reset();
        directory = Directory.load(Info.getHome());
        Info.loadInfo();
        log("");

        keysTree = new JTree(mkKeysTree(directory));
        keysTree.setCellRenderer(new MyTreeRenderer());
        keysTree.addMouseListener(new MyMouseListener());
//            expandAll(keysTree);
        for (Component component : keysPanel.getComponents()) {
            if (component instanceof JScrollPane)
                keysPanel.remove(component);
        }
        keysPanel.add(new JScrollPane(keysTree));
        if (secKeysExpanded)
            keysTree.expandPath(new TreePath(secKeyBranch.getPath()));
        if (listsExpanded)
            keysTree.expandPath(new TreePath(listsBranch.getPath()));
        if (directoryExpanded)
            keysTree.expandPath(new TreePath(directoryBranch.getPath()));
        keysPanel.revalidate();

        secKeyBranch.removeAllChildren();
        for (Key key : KeyDB2.getInstance().getSecretKeys())
            secKeyBranch.add(mkTreeKey(key));

        keysPanel.revalidate();
    }

    private void expandAll(JTree tree) {
        int row = 0;
        while (row < tree.getRowCount()) {
            tree.expandRow(row);
            row++;
        }
    }

    private DefaultMutableTreeNode mkKeysTree(Directory directory) {
        DefaultMutableTreeNode keysTreeRoot = new DefaultMutableTreeNode(Text.get("keys"));

        secKeyBranch = new DefaultMutableTreeNode(Text.get("secret_keys"));
        keysTreeRoot.add(secKeyBranch);
        for (Key key : KeyDB2.getInstance().getSecretKeys())
            secKeyBranch.add(mkTreeKey(key));

        listsBranch = new DefaultMutableTreeNode(Text.get("lists"));
        keysTreeRoot.add(listsBranch);
        for (KeyList list : KeyListDB.getInstance().getListSet())
            listsBranch.add(mkTreeList(list));

        directoryBranch = mkTreeDirectory(directory);
        keysTreeRoot.add(directoryBranch);

        return keysTreeRoot;
    }

    private DefaultMutableTreeNode mkTreeList(KeyList list) {
        DefaultMutableTreeNode node = new DefaultMutableTreeNode(list);
        for (Key key : list.getMembers())
            node.add(mkTreeKey(key));
        return node;
    }

    private DefaultMutableTreeNode mkTreeDirectory(Directory directory) {
        DefaultMutableTreeNode node = new DefaultMutableTreeNode(directory);
        for (Key key : directory.getKeys())
            node.add(mkTreeKey(key));
        for (Directory sub : directory.getSubdirs())
            node.add(mkTreeDirectory(sub));
        return node;
    }

    private DefaultMutableTreeNode mkTreeKey(Key key) {
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
    private DefaultMutableTreeNode mkTreeKey(Key key, Set<Long> hierarchy) {
        DefaultMutableTreeNode node = new DefaultMutableTreeNode(key);
        node.add(new DefaultMutableTreeNode(key.getCorePresentation()));
        node.add(new DefaultMutableTreeNode(key.getIdFingerprint()));
        PGPPublicKey publicKey = key.getPublicKey();
        PGPPublicKey encryptingKey = key.getEncryptingKey();
        StringBuilder builder = new StringBuilder();
        builder.append(ToString.publicKey(publicKey.getAlgorithm()))
                .append(" (").append(getBits(publicKey)).append(")");
        if (encryptingKey != null)
            builder.append(" / ")
                    .append(ToString.publicKey(encryptingKey.getAlgorithm()))
                    .append(" (").append(getBits(encryptingKey)).append(")");
        node.add(new DefaultMutableTreeNode(builder.toString()));

        List<Long> signerList = key.getSigIds();
        if (signerList.size() > 0) {
            Set<Long> extHierarchy = new HashSet<Long>(hierarchy);
            extHierarchy.addAll(signerList);
            DefaultMutableTreeNode signers = new DefaultMutableTreeNode(Text.get("signers") + " ...");
            node.add(signers);
            for (Long sid : signerList) {
                Key signerKey = KeyDB2.getInstance().getKey(sid);
                if (signerKey == null)
                    signers.add(new DefaultMutableTreeNode(String.format("[%s]", Key.mkId8(sid))));
                else if (hierarchy.contains(sid))
                    signers.add(new DefaultMutableTreeNode(String.format("[%s] %s", Key.mkId8(sid), signerKey.toString())));
                else
                    signers.add(mkTreeKey(signerKey, extHierarchy));
            }
        }
        return node;
    }

    private int getBits(PGPPublicKey publicKey) {
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

    private X9ECParameters getECParameters(BCPGKey key) {
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
        if (parameters != null)
            return parameters;
        return null;
    }

    public Component getPanel() {
        Preferences preferences = Preferences.userRoot().node("mypgp");

        fch = new MyFileChooser();
        fch.setPreferences(preferences);
        String wd = preferences.get("working_dir", null);
        if (wd != null) {
            File wdFile = new File(wd);
            if (wdFile.exists() && wdFile.isDirectory())
                fch.setDirectory(wdFile);
        }

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        processButton = new JButton(Text.get("process"));
        encryptButton = new JButton(Text.get("encrypt"));
        buttons.add(processButton);
        buttons.add(encryptButton);

        processButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent event) {
                File[] files = fch.getSelectedFiles();
                if (files == null || files.length == 0)
                    return;
                processSelection(files);
                fch.rescanCurrentDirectory();
                fch.setSelectedFiles(files);
            }
        });
        encryptButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent event) {
                File[] files = fch.getSelectedFiles();
                if (files == null || files.length == 0)
                    return;
                encryptSelection(files);
                fch.rescanCurrentDirectory();
                fch.setSelectedFiles(files);
            }
        });

        keysPanel = new JPanel(new BorderLayout());
        keysPanel.add(new JScrollPane(keysTree));

        JPanel dirPanel = new JPanel(new BorderLayout());
        JToolBar rightToolBar = new JToolBar();
        rightToolBar.setFloatable(false);
        newDirectoryAction = new NewDirectoryAction();
        rightToolBar.add(newDirectoryAction);
        rightToolBar.addSeparator(new Dimension(5, 5));
        refreshAction = new RefreshAction();
        rightToolBar.add(refreshAction);
        rightToolBar.addSeparator(new Dimension(5, 5));
        secureDeleteAction = new SecureDeleteAction();
        rightToolBar.add(secureDeleteAction);
        dirPanel.add(rightToolBar, BorderLayout.NORTH);
        dirPanel.add(fch, BorderLayout.CENTER);
        dirPanel.add(buttons, BorderLayout.SOUTH);

        SpringLayout layout = new SpringLayout();
        JPanel panel = new JPanel(layout);

        panel.add(keysPanel);
        SpringLayout.Constraints keysPanelConstraints = layout.getConstraints(keysPanel);
        keysPanelConstraints.setX(Spring.constant(0));
        keysPanelConstraints.setY(Spring.constant(0));

        panel.add(dirPanel);
        SpringLayout.Constraints dirPanelConstraints = layout.getConstraints(dirPanel);
        dirPanelConstraints.setX(keysPanelConstraints.getConstraint("East"));
        dirPanelConstraints.setY(Spring.constant(0));

        JScrollPane logAreaPane = new JScrollPane(logArea);
        panel.add(logAreaPane);
        SpringLayout.Constraints logAreaConstraints = layout.getConstraints(logAreaPane);
        logAreaConstraints.setX(dirPanelConstraints.getConstraint("West"));
        logAreaConstraints.setY(dirPanelConstraints.getConstraint("South"));
        logAreaConstraints.setWidth(dirPanelConstraints.getWidth());

        Spring totalHeight = Spring.sum(
                dirPanelConstraints.getHeight(),
                logAreaConstraints.getHeight());
        keysPanelConstraints.setHeight(totalHeight);

        SpringLayout.Constraints windowConstraints = layout.getConstraints(panel);
        windowConstraints.setConstraint("East", dirPanelConstraints.getConstraint("East"));
        windowConstraints.setConstraint("South", keysPanelConstraints.getConstraint("South"));

        return panel;
    }

    private void processSelection(File[] files) {
        Map<Long, char[]> passwords = new HashMap<Long, char[]>();
        try {
            for (File blackFile : files) {
                try {
                    BcUtilsFiles.process(blackFile, passwords);
                } catch (PasswordCancelled ignored) {
                } catch (PGPException e) {
                    log2(e.toString());
                    if (e.getUnderlyingException() != null)
                        MyLogger.dump(e.getUnderlyingException(), Text.get("process"));
                } catch (Exception e) {
                    MyLogger.dump(e, Text.get("process"));
                }
            }
        } finally {
            for (char[] password : passwords.values())
                Arrays.fill(password, '*');
        }
    }

    private void encryptSelection(File[] files) {
        log("");
        List<Key> encryptingKeys = getEncryptingKeys();
        if (encryptingKeys.size() == 0) {
            log("%s: 0%n", Text.get("public_keys"));
            return;
        }
        for (File redFile : files) {
            log(Text.get("encrypt") + " " + redFile.getName());
            try {
                BcUtilsFiles.encrypt(redFile, encryptingKeys);
            } catch (PGPException e) {
                log2(e.toString());
                if (e.getUnderlyingException() != null)
                    MyLogger.dump(e.getUnderlyingException(), Text.get("encrypt"));
            } catch (Exception e) {
                MyLogger.dump(e, Text.get("encrypt"));
            }
        }
    }

    private JMenuBar getMenuBar() {
        JMenuBar menuBar = new JMenuBar();
        JMenu keyMenu = new JMenu(Text.get("keys"));
        menuBar.add(keyMenu);
        keyMenu.add(new GenerateKeyAction());
        keyMenu.add(new AliasKeyAction());
        keyMenu.add(new CopyKeyAction());
        keyMenu.add(new ExportKeyAction());
        keyMenu.add(new ReloadKeysAction());
        keyMenu.add(new FileMapAction());

        JMenu listsMenu = new JMenu(Text.get("lists"));
        menuBar.add(listsMenu);
        listsMenu.add(new AddKeyListAction());
        listsMenu.add(new RemoveKeyListAction());
        listsMenu.add(new NewListAction());
        listsMenu.add(new RemoveListAction());

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
                    newDirectoryAction.putValue(Action.NAME, Text.get("new_directory"));
                    refreshAction.putValue(Action.NAME, Text.get("refresh"));
                    secureDeleteAction.putValue(Action.NAME, Text.get("delete"));
                    processButton.setText(Text.get("process"));
                    encryptButton.setText(Text.get("encrypt"));
                    frame.setJMenuBar(getMenuBar());
                    frame.validate();
                }
            });
            langMenu.add(item);
        }

        return menuBar;
    }

    private List<Key> getSecretKeys() {
        List<Key> keys = new ArrayList<Key>();
        TreePath[] paths = keysTree.getSelectionPaths();
        if (paths == null || paths.length == 0)
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

    private List<Key> getSigningKeys() {
        List<Key> keys = new ArrayList<Key>();
        for (Key key : getSecretKeys()) {
            if (key.getSigningKey() != null)
                keys.add(key);
        }
        log(Text.get("sign"));
        for (Key key : keys)
            log2(key.toString());
        return keys;
    }

    private List<Key> getPublicKeys() {
        List<Key> keys = new ArrayList<Key>();
        TreePath[] paths = keysTree.getSelectionPaths();
        if (paths == null || paths.length == 0)
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
                for (Key key : list.getMembers())
                    keys.add(key);

            } else if (object.getClass() == Directory.class) {
                Directory directory = (Directory) object;
                directory.addKeys(keys);

            }
        }
        return keys;
    }

    private List<Key> getEncryptingKeys() {
        List<Key> keys = new ArrayList<Key>();
        for (Key key : getPublicKeys()) {
            if (key.getEncryptingKey() != null)
                keys.add(key);
        }
        log(Text.get("encrypt"));
        for (Key key : keys)
            log2(key.toString());
        return keys;
    }

    private List<DefaultMutableTreeNode> getLists() {
        List<DefaultMutableTreeNode> lists = new ArrayList<DefaultMutableTreeNode>();
        TreePath[] paths = keysTree.getSelectionPaths();
        if (paths == null || paths.length == 0)
            return lists;

        for (TreePath path : paths) {
            DefaultMutableTreeNode node = (DefaultMutableTreeNode) path.getLastPathComponent();
            Object object = node.getUserObject();
            if (object.getClass() == KeyList.class)
                lists.add(node);
        }
        return lists;
    }

    public void log1(String msg) {
        log("");
        log(msg);
    }

    public void log2(String msg) {
        log("  " + msg);
    }

    public void log(String line) {
        if (line == null)
            return;
        if (line.length() > 0)
            logArea.append(line);
        logArea.append("\n");
        logArea.setCaretPosition(logArea.getDocument().getLength());
    }

    public Window getWindow() {
        return frame;
    }

    public void ignore(String absolutePath) {
        if (absolutePath.toLowerCase().endsWith(".jar"))
            return;
        getInstance().log(Text.get("skip") + " " + absolutePath);
    }

    private class EncryptAction
            extends AbstractAction {
        private EncryptAction() {
            super(Text.get("encrypt"));
        }

        public void actionPerformed(ActionEvent event) {
            log1(Text.get("encrypt"));
            File[] files = fch.getSelectedFiles();
            if (files == null || files.length == 0)
                return;
            encryptSelection(files);
            fch.rescanCurrentDirectory();
            fch.setSelectedFiles(files);
        }
    }

    private class SignAction
            extends AbstractAction {
        private SignAction() {
            super(Text.get("sign"));
        }

        public void actionPerformed(ActionEvent event) {
            File[] files = fch.getSelectedFiles();
            if (files == null || files.length == 0)
                return;

            List<Key> signingKeys = getSigningKeys();
            if (signingKeys.isEmpty()) {
                log("%s: %d%n", Text.get("secret_keys"), signingKeys.size());
                return;
            }

            Map<Key, char[]> passwords = new HashMap<Key, char[]>();
            try {
                for (Key signingKey : signingKeys) {
                    char[] password = GetPassword.getInstance().getDecryptionPassword(signingKey.toString());
                    passwords.put(signingKey, password);
                }
            } catch (PasswordCancelled passwordCancelled) {
                return;
            }

            for (File redFile : files) {
                try {
                    log1(Text.get("sign") + " " + redFile.getName());
                    BcUtilsFiles.sign(redFile, signingKeys, passwords);
                } catch (PGPException e) {
                    log2(e.toString());
                    if (e.getUnderlyingException() != null)
                        MyLogger.dump(e.getUnderlyingException(), Text.get("sign"));
                } catch (Exception e) {
                    MyLogger.dump(e, Text.get("sign"));
                }
            }

            for (char[] password : passwords.values())
                Arrays.fill(password, '*');
            fch.rescanCurrentDirectory();
            fch.setSelectedFiles(files);
        }
    }

    private class EncryptSignAction
            extends AbstractAction {
        private EncryptSignAction() {
            super(Text.get("encrypt_sign"));
        }

        public void actionPerformed(ActionEvent event) {
            log1(Text.get("encrypt_sign"));
            File[] files = fch.getSelectedFiles();
            if (files == null || files.length == 0)
                return;

            List<Key> encryptingKeys = getEncryptingKeys();
            if (encryptingKeys.size() == 0) {
                log("%s: 0%n", Text.get("public_keys"));
                return;
            }

            List<Key> signingKeys = getSigningKeys();
            if (signingKeys.isEmpty()) {
                log("%s: %d%n", Text.get("secret_keys"), signingKeys.size());
                return;
            }

            Map<Key, char[]> passwords = new HashMap<Key, char[]>();
            try {
                for (Key signingKey : signingKeys) {
                    char[] password = GetPassword.getInstance().getDecryptionPassword(signingKey.toString());
                    passwords.put(signingKey, password);
                }
            } catch (PasswordCancelled passwordCancelled) {
                return;
            }

            for (File redFile : files) {
                try {
                    log(Text.get("encrypt_sign") + " " + redFile.getName());
                    BcUtilsFiles.encrypt_sign(redFile, signingKeys, encryptingKeys, passwords);
                } catch (PGPException e) {
                    log2(e.toString());
                    if (e.getUnderlyingException() != null)
                        MyLogger.dump(e.getUnderlyingException(), Text.get("encrypt_sign"));
                } catch (Exception e) {
                    MyLogger.dump(e, Text.get("encrypt_sign"));
                }
            }

            for (char[] password : passwords.values())
                Arrays.fill(password, '*');
            fch.rescanCurrentDirectory();
            fch.setSelectedFiles(files);
        }
    }

    private class DecryptAction
            extends AbstractAction {
        private DecryptAction() {
            super(Text.get("decrypt_verify"));
        }

        public void actionPerformed(ActionEvent event) {
            log1(Text.get("decrypt_verify"));
            File[] files = fch.getSelectedFiles();
            if (files == null || files.length == 0)
                return;
            processSelection(files);
            fch.rescanCurrentDirectory();
            fch.setSelectedFiles(files);
        }
    }

    private class ViewClipAction
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

    private class EncryptClipAction
            extends AbstractAction {
        private EncryptClipAction() {
            super(Text.get("encrypt"));
        }

        public void actionPerformed(ActionEvent event) {
            List<Key> encryptingKeys = getEncryptingKeys();
            if (encryptingKeys.size() == 0) {
                log("%s: 0%n", Text.get("public_keys"));
                return;
            }

            try {
                log(Text.get("encrypt") + " " + Text.get("clipboard"));
                String redText = MyClipBoard.readString();
                String blackText = BcUtilsClipboard.encrypt(redText, encryptingKeys);
                MyClipBoard.write(blackText);
            } catch (PGPException e) {
                log2(e.toString());
                if (e.getUnderlyingException() != null)
                    MyLogger.dump(e.getUnderlyingException(), Text.get("encrypt"));
            } catch (Exception e) {
                MyLogger.dump(e, Text.get("encrypt"));
            }
        }
    }

    private class SignClipAction
            extends AbstractAction {
        private SignClipAction() {
            super(Text.get("sign"));
        }

        public void actionPerformed(ActionEvent event) {
            List<Key> signingKeys = getSigningKeys();
            if (signingKeys.size() != 1) {
                log("%s: %d%n", Text.get("secret_keys"), signingKeys.size());
                return;
            }
            Key signingKey = signingKeys.get(0);
            try {
                log(Text.get("sign") + " " + Text.get("clipboard"));
                String redText = MyClipBoard.readString();
                char[] password = GetPassword.getInstance().getDecryptionPassword(Text.get("sign"));
                String blackText = BcUtilsClipboard.clearsign(redText, signingKey, password);
                MyClipBoard.write(blackText);
            } catch (PasswordCancelled ignored) {
            } catch (PGPException e) {
                log2(e.toString());
                if (e.getUnderlyingException() != null)
                    MyLogger.dump(e.getUnderlyingException(), Text.get("sign"));
            } catch (Exception e) {
                MyLogger.dump(e, Text.get("sign"));
            }
        }
    }

    private class EncryptSignClipAction
            extends AbstractAction {
        private EncryptSignClipAction() {
            super(Text.get("encrypt_sign"));
        }

        public void actionPerformed(ActionEvent event) {
            log1(Text.get("encrypt_sign"));
            List<Key> encryptingKeys = getEncryptingKeys();
            if (encryptingKeys.size() == 0) {
                log("%s: 0%n", Text.get("public_keys"));
                return;
            }

            List<Key> signingKeys = getSigningKeys();
            if (signingKeys.size() != 1) {
                log("%s: %d%n", Text.get("secret_keys"), signingKeys.size());
                return;
            }
            Key signingKey = signingKeys.get(0);

            try {
                log(Text.get("encrypt_sign") + " " + Text.get("clipboard"));
                String redText = MyClipBoard.readString();
                char[] password = GetPassword.getInstance().getDecryptionPassword(Text.get("sign"));
                String blackText = BcUtilsClipboard.encrypt_sign(redText, encryptingKeys, signingKey, password);
                MyClipBoard.write(blackText);
            } catch (PasswordCancelled ignored) {
            } catch (PGPException e) {
                log2(e.toString());
                if (e.getUnderlyingException() != null)
                    MyLogger.dump(e.getUnderlyingException(), Text.get("encrypt_sign"));
            } catch (Exception e) {
                MyLogger.dump(e, Text.get("encrypt_sign"));
            }
        }
    }

    private class DecryptClipAction
            extends AbstractAction {
        private DecryptClipAction() {
            super(Text.get("decrypt_verify"));
        }

        public void actionPerformed(ActionEvent event) {
            log1(Text.get("decrypt_verify") + " " + Text.get("clipboard"));
            try {
                String blackText = MyClipBoard.readString();
                String redText = BcUtilsClipboard.process(blackText);
                MyClipBoard.write(redText);
            } catch (PasswordCancelled ignored) {
            } catch (PGPException e) {
                log2(e.toString());
                if (e.getUnderlyingException() != null)
                    MyLogger.dump(e.getUnderlyingException(), Text.get("decrypt_verify"));
            } catch (Exception e) {
                MyLogger.dump(e, Text.get("decrypt_verify"));
            }
        }
    }

    private class SecureDeleteAction
            extends AbstractAction {
        private SecureDeleteAction() {
            super(Text.get("delete"));
        }

        public void actionPerformed(ActionEvent event) {
            log1(Text.get("delete"));
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
                            Text.get("delete"),
                            JOptionPane.OK_CANCEL_OPTION,
                            JOptionPane.QUESTION_MESSAGE,
                            Icons.getPgpIcon());
                    if (result != JOptionPane.OK_OPTION)
                        return;
                    log(Text.get("delete") + ": " + file.getName());
                    SecureDeleter.delete(MyPGP.this, file);
                } catch (Exception e) {
                    MyLogger.dump(e, Text.get("delete"));
                }
            }
            fch.rescanCurrentDirectory();
        }
    }

    public void fileDeleted(SecureDeleteWorker worker) {
        try {
            fch.rescanCurrentDirectory();
            Exception executonException = worker.getExecutonException();
            if (executonException != null)
                throw executonException;
        } catch (Exception e) {
            MyLogger.dump(e, Text.get("delete"));
        }
    }

    private class NewDirectoryAction
            extends AbstractAction {

        private NewDirectoryAction() {
            super(Text.get("new_directory"));
        }

        public void actionPerformed(ActionEvent event) {
            File father = null;
            try {
                father = getDirectory(fch);
            } catch (FileNotFoundException ignored) {
            }
            if (father == null)
                return;
            String label = Text.get("new_directory");
            JTextField textField = new JTextField(20);
            int result = JOptionPane.showConfirmDialog(null,
                    textField, label,
                    JOptionPane.OK_CANCEL_OPTION,
                    JOptionPane.QUESTION_MESSAGE,
                    Icons.getPgpIcon());
            if (result != JOptionPane.OK_OPTION)
                return;
            String dirname = textField.getText();
            if (dirname == null || dirname.length() == 0)
                return;
            File son = new File(father, dirname);
            son.mkdir();
            fch.setDirectory(son);
        }
    }

    private class RefreshAction
            extends AbstractAction {
        private RefreshAction() {
            super(Text.get("refresh"));
        }

        public void actionPerformed(ActionEvent event) {
            fch.rescanCurrentDirectory();
        }
    }

    private class GenerateKeyAction
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
            log1(Text.get("generate"));

            KeyGeneratingThread task = new KeyGeneratingThread(
                    where,
                    panel.getSignAlgo(), panel.getSignSize(),
                    panel.getEncryptAlgo(), panel.getEncryptSize(),
                    panel.getName(), panel.getEmail(), panel.getComment(),
                    panel.getExpireDate(),
                    panel.getPassword());
            KeyGeneratingWorker worker = new KeyGeneratingWorker(MyPGP.this, task);
            worker.execute();
        }
    }

    public void keyGenerated(KeyGeneratingThread task) {
        try {
            long delta = task.getDelta();
            log2(String.format("%dm %ds", delta / 60, delta % 60));
            Exception executionException = task.getExecutionException();
            if (executionException != null)
                throw executionException;
            log2(task.getResult());
            reloadKeys();
        } catch (Exception e) {
            if (e instanceof PGPException) {
                PGPException pgpException = (PGPException) e;
                log2(pgpException.toString());
                if (pgpException.getUnderlyingException() != null)
                    MyLogger.dump(pgpException.getUnderlyingException(), Text.get("generate"));
            } else {
                MyLogger.dump(e, Text.get("generate"));
            }
        }
    }

    private class AliasKeyAction
            extends AbstractAction {
        private AliasKeyAction() {
            super(Text.get("alias"));
        }

        public void actionPerformed(ActionEvent event) {
            List<Key> secretKeys = getSecretKeys();
            List<Key> publicKeys = getPublicKeys();
            if (secretKeys.size() == 0 && publicKeys.size() == 0) {
                log("%s: 0%n", Text.get("public_keys"));
                log("%s: 0%n", Text.get("secret_keys"));
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
            KeyDB2.getInstance().setAlias(key.getKid(), aliasLabel.getText());
        }
    }

    private class CopyKeyAction
            extends AbstractAction {
        private CopyKeyAction() {
            super(Text.get("copy"));
        }

        public void actionPerformed(ActionEvent event) {
            List<Key> secretKeys = getSecretKeys();
            List<Key> publicKeys = getPublicKeys();
            if (secretKeys.size() == 0 && publicKeys.size() == 0) {
                log("%s: 0%n", Text.get("public_keys"));
                log("%s: 0%n", Text.get("secret_keys"));
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

    private class ExportKeyAction
            extends AbstractAction {
        private ExportKeyAction() {
            super(Text.get("export"));
        }

        public void actionPerformed(ActionEvent event) {
            log1(Text.get("export"));
            List<Key> secretKeys = getSecretKeys();
            List<Key> publicKeys = getPublicKeys();
            if (secretKeys.size() == 0 && publicKeys.size() == 0) {
                log("%s: 0%n", Text.get("public_keys"));
                log("%s: 0%n", Text.get("secret_keys"));
                return;
            }
            File where = getFile(Text.get("export"));
            if (where == null)
                return;

            for (Key key : secretKeys) {
                log2(key.toString());
                KeySaver.exportSecretKey(where, key);
            }
            for (Key key : publicKeys) {
                log2(key.toString());
                KeySaver.exportPublicKey(where, key);
            }
        }

        private File getFile(String s) {
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

    private class ReloadKeysAction
            extends AbstractAction {
        private ReloadKeysAction() {
            super(Text.get("refresh"));
        }

        public void actionPerformed(ActionEvent event) {
            reloadKeys();
        }
    }

    private class FileMapAction
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

    private class AddKeyListAction
            extends AbstractAction {
        private AddKeyListAction() {
            super(Text.get("add_key_list"));
        }

        public void actionPerformed(ActionEvent event) {
            List<Key> publicKeys = getPublicKeys();
            if (publicKeys.size() == 0) {
                log("%s: 0%n", Text.get("public_keys"));
                return;
            }

            List<DefaultMutableTreeNode> listNodes = getLists();
            if (listNodes.size() == 0) {
                log("%s: 0%n", Text.get("lists"));
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

    private class RemoveKeyListAction
            extends AbstractAction {
        private RemoveKeyListAction() {
            super(Text.get("remove_key_list"));
        }

        public void actionPerformed(ActionEvent event) {
            TreePath[] paths = keysTree.getSelectionPaths();
            if (paths == null || paths.length == 0)
                return;

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

    private class NewListAction
            extends AbstractAction {
        private NewListAction() {
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
            if (KeyListDB.getInstance().get(listname) != null)
                return;
            KeyList list = new KeyList(listname);
            KeyListDB.getInstance().add(list);
            Info.saveInfo();
            reloadKeys();
        }
    }

    private class RemoveListAction
            extends AbstractAction {
        private RemoveListAction() {
            super(Text.get("remove_list"));
        }

        public void actionPerformed(ActionEvent event) {
            List<DefaultMutableTreeNode> listNodes = getLists();
            if (listNodes.size() == 0) {
                log("%s: 0%n", Text.get("lists"));
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
                KeyListDB.getInstance().removeList(list);
            }
            Info.saveInfo();
            reloadKeys();
        }
    }

    private File getDirectory(MyFileChooser fch)
            throws FileNotFoundException {
        File directory = fch.getSelectedFile();
        if (directory == null || !directory.isDirectory())
            directory = fch.getCurrentDirectory();
        if (directory == null)
            throw new FileNotFoundException("destination");
        if (directory.isDirectory())
            return directory;
        return directory.getParentFile();
    }

    private void log(String format, String text) {
        logArea.append(String.format(format, text));
        logArea.setCaretPosition(logArea.getDocument().getLength());
    }

    private void log(String format, String text, int number) {
        logArea.append(String.format(format, text, number));
        logArea.setCaretPosition(logArea.getDocument().getLength());
    }

    private boolean keyInSecretList(TreePath path) {
        DefaultMutableTreeNode last = (DefaultMutableTreeNode) path.getLastPathComponent();
        Object x = last.getUserObject();
        if (x.getClass() != Key.class)
            return false;
        DefaultMutableTreeNode node = (DefaultMutableTreeNode) path.getPathComponent(path.getPathCount() - 2);
        return node == secKeyBranch;
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
            popupKeyInRings.add(new AliasKeyAction());
            popupKeyInRings.add(new CopyKeyAction());
            popupKeyInRings.add(new ExportKeyAction());
        }
        popupKeyInRings.show(keysTree, x, y);
    }

    private void doKeyInPublicList(int x, int y) {
        if (popupKeyInRings == null) {
            popupKeyInRings = new JPopupMenu();
            popupKeyInRings.add(new AliasKeyAction());
            popupKeyInRings.add(new CopyKeyAction());
            popupKeyInRings.add(new ExportKeyAction());
        }
        popupKeyInRings.show(keysTree, x, y);
    }

    private void doList(int x, int y) {
        if (popupList == null) {
            popupList = new JPopupMenu();
            popupList.add(new RemoveKeyListAction());
            popupList.add(new NewListAction());
            popupList.add(new RemoveListAction());
        }
        popupList.show(keysTree, x, y);
    }

    private void doKeyInList(int x, int y) {
        if (popupKeyInList == null) {
            popupKeyInList = new JPopupMenu();
            popupKeyInList.add(new AliasKeyAction());
            popupKeyInRings.add(new CopyKeyAction());
            popupKeyInList.add(new ExportKeyAction());
            popupKeyInList.add(new RemoveKeyListAction());
        }
        popupKeyInList.show(keysTree, x, y);
    }

    private class MyMouseListener
            extends MouseAdapter {
        @Override
        public void mousePressed(MouseEvent me) {
            if (me.getButton() != MouseEvent.BUTTON3)
                return;
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
    }
}

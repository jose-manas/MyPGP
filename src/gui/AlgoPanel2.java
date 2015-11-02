package gui;

import gui.imgs.Icons;

import javax.swing.*;
import javax.swing.plaf.basic.BasicArrowButton;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

/**
 * @author Jose A. Manas
 * @version 17.8.2014
 */
public class AlgoPanel2
        extends JPanel {
    public static final String RSA = "RSA";
    public static final String DSA = "DSA";
    public static final String ECDSA = "ECDSA";
    public static final String ELGAMAL_IETF = "Elgamal /IETF";
    public static final String ELGAMAL_GNUPG = "Elgamal /GnuPG";
    public static final String ELGAMAL = "Elgamal";
    public static final String ECDH = "ECDH";

    public static final int CURVE_25519 = -1;

    private final JCheckBox sign;
    private final JTextField signAlgo;
    private static String selectedSignAlgo = RSA;
    private static int selectedSignSize = 2048;

    private final JCheckBox encrypt;
    private final JTextField encryptAlgo;
    private static String selectedEncryptAlgo = RSA;
    private static int selectedEncryptSize = 2048;

    public AlgoPanel2() {
        super(new SpringLayout());

        sign = new JCheckBox(Text.get("sign"));
        signAlgo = new JTextField(20);
        signAlgo.setText(String.format("%s (%d)", selectedSignAlgo, selectedSignSize));
        JButton signAlgoSel = new BasicArrowButton(BasicArrowButton.SOUTH);
        signAlgoSel.addActionListener(new SignSelectionAction());

        encrypt = new JCheckBox(Text.get("encrypt"));
        encryptAlgo = new JTextField(20);
        encryptAlgo.setText(String.format("%s (%d)", selectedEncryptAlgo, selectedEncryptSize));
        JButton encryptAlgoSel = new BasicArrowButton(BasicArrowButton.SOUTH);
        encryptAlgoSel.addActionListener(new EncryptSelectionAction());

        sign.setSelected(true);
        sign.setEnabled(false);

        encrypt.setSelected(true);

        JComponent[][] table = new JComponent[][]{
                {sign, blank(), encrypt, blank()},
                {signAlgo, signAlgoSel, encryptAlgo, encryptAlgoSel},
        };

        //Create the panel and populate it.
        for (JComponent[] row : table) {
            for (JComponent component : row)
                add(component);
        }

        //Lay out the panel.
        SpringUtilities.makeCompactGrid(this,
                2, 4, //rows, cols
                5, 5, //initialX, initialY
                5, 5);//xPad, yPad

    }

    private static JLabel blank() {
        return new JLabel("");
    }

    public String getSignAlgo() {
        return selectedSignAlgo;
    }

    public int getSignSize() {
        try {
            return selectedSignSize;
        } catch (Exception e) {
            return 0;
        }
    }

    public String getEncryptAlgo() {
        if (encrypt.isSelected())
            return selectedEncryptAlgo;
        else
            return null;
    }

    public int getEncryptSize() {
        try {
            if (encrypt.isSelected())
                return selectedEncryptSize;
            else
                return 0;
        } catch (Exception e) {
            return 0;
        }
    }

    private class SignSelectionAction
            implements ActionListener {
        private final JPopupMenu popupMenu;

        public SignSelectionAction() {
            popupMenu = new JPopupMenu("sign");
            add(popupMenu, RSA, 1024, 2048, 3072, 4096);
            add(popupMenu, DSA, 1024, 2048, 3072, 4096);
            // NIST FIPS-PUB 186-4 July 2013
//          "B-163", "B-233", "B-283", "B-409", "B-571"
//          "K-163", "K-233", "K-283", "K-409", "K-571"
//          "P-192", "P-224", "P-256", "P-384", "P-521"
            add(popupMenu, ECDSA, 192, 224, 256, 384, 521);
//            add(popupMenu, ECDSA, 192, 224, 256, CURVE_25519, 384, 521);
        }

        private void add(JPopupMenu popupMenu, String algo, int... sizes) {
            JMenu menu = new JMenu(algo);
            popupMenu.add(menu);
            for (int size : sizes)
                if (size == CURVE_25519)
                    menu.add(new SignOption_Curve25519());
                else
                    menu.add(new SignOption(algo, size));
        }

        public void actionPerformed(ActionEvent event) {
            popupMenu.show((JComponent) event.getSource(), 10, 10);
        }
    }

    private class SignOption_Curve25519
            extends JMenuItem {
        private static final String TITLE = "ECDSA (Curve-25519)";

        public SignOption_Curve25519() {
            super(TITLE);
            addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    selectedSignAlgo = ECDSA;
                    selectedSignSize = -1;
                    signAlgo.setText(TITLE);
                }
            });
        }
    }

    private class SignOption
            extends JMenuItem {
        public SignOption(final String algo, final int size) {
            super(String.format("%s (%d)", algo, size));
            addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    selectedSignAlgo = algo;
                    selectedSignSize = size;
                    signAlgo.setText(String.format("%s (%d)", algo, size));
                }
            });
        }
    }

    private class EncryptSelectionAction
            implements ActionListener {
        private final JPopupMenu popupMenu;

        public EncryptSelectionAction() {
            popupMenu = new JPopupMenu("encrypt");
            add(popupMenu, RSA, 1024, 2048, 3072, 4096);
            add(popupMenu, ELGAMAL_IETF, 1024, 1536, 2048, 3072, 4096);
            add(popupMenu, ELGAMAL_GNUPG, 1024, 1536, 2048, 3072, 4096);
            add(popupMenu, ELGAMAL, 1024, 1536, 2048, 3072, 4096);
            // NIST FIPS-PUB 186-4 July 2013
//          "B-163", "B-233", "B-283", "B-409", "B-571"
//          "K-163", "K-233", "K-283", "K-409", "K-571"
//          "P-192", "P-224", "P-256", "P-384", "P-521"
            add(popupMenu, ECDH, 192, 224, 256, 384, 521);
        }

        private void add(JPopupMenu popupMenu, String algo, int... sizes) {
            JMenu menu = new JMenu(algo);
            popupMenu.add(menu);
            for (int size : sizes)
                menu.add(new EncryptOption(algo, size));
        }

        public void actionPerformed(ActionEvent event) {
            if (encrypt.isSelected())
                popupMenu.show((JComponent) event.getSource(), 10, 10);
        }
    }

    private class EncryptOption
            extends JMenuItem {
        public EncryptOption(final String algo, final int size) {
            super(String.format("%s (%d)", algo, size));
            addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    selectedEncryptAlgo = algo;
                    selectedEncryptSize = size;
                    encryptAlgo.setText(String.format("%s (%d)", algo, size));
                }
            });
        }
    }

    public static void main(String[] args) {
        JPanel panel = new AlgoPanel2();
        JFrame frame = new JFrame("AlgoPanel2");
        frame.setIconImage(Icons.getPgpImage());
        frame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);

        panel.setOpaque(true);
        frame.setContentPane(panel);

        frame.pack();
        frame.setVisible(true);
    }
}
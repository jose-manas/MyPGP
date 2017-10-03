package gui;

import crypto.CryptoAlgo;
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
    private static final String RSA = "RSA";
    private static final String DSA = "DSA";
    private static final String ECDSA = "ECDSA";
    private static final String ELGAMAL_IETF = "Elgamal /IETF";
    private static final String ELGAMAL_GNUPG = "Elgamal /GnuPG";
    private static final String ELGAMAL = "Elgamal";
    private static final String ECDH = "ECDH";

    private final JCheckBox sign;
    private final JTextField signAlgo;
    private static String selectedSignAlgo = CryptoAlgo.RSA_2048;

    private final JCheckBox encrypt;
    private final JTextField encryptAlgo;
    private static String selectedEncryptAlgo = CryptoAlgo.RSA_2048;

    AlgoPanel2() {
        super(new SpringLayout());

        sign = new JCheckBox(Text.get("sign"));
        signAlgo = new JTextField(20);
        signAlgo.setText(selectedSignAlgo);
        JButton signAlgoSel = new BasicArrowButton(BasicArrowButton.SOUTH);
        signAlgoSel.addActionListener(new SignSelectionAction());

        encrypt = new JCheckBox(Text.get("encrypt"));
        encryptAlgo = new JTextField(20);
        encryptAlgo.setText(selectedEncryptAlgo);
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
    
    String getSignAlgo() {
        return selectedSignAlgo;
    }
    
    String getEncryptAlgo() {
        if (encrypt.isSelected())
            return selectedEncryptAlgo;
        else
            return null;
    }
    
    private class SignSelectionAction
            implements ActionListener {
        private final JPopupMenu popupMenu;

        SignSelectionAction() {
            popupMenu = new JPopupMenu("sign");
            add(popupMenu, RSA,
                    CryptoAlgo.RSA_1024,
                    CryptoAlgo.RSA_2048,
                    CryptoAlgo.RSA_3072,
                    CryptoAlgo.RSA_4096);
            add(popupMenu, DSA,
                    CryptoAlgo.DSA_1024,
                    CryptoAlgo.DSA_2048,
                    CryptoAlgo.DSA_3072,
                    CryptoAlgo.DSA_4096);
            // NIST FIPS-PUB 186-4 July 2013
//          "B-163", "B-233", "B-283", "B-409", "B-571"
//          "K-163", "K-233", "K-283", "K-409", "K-571"
//          "P-192", "P-224", "P-256", "P-384", "P-521"
            add(popupMenu, ECDSA,
                    CryptoAlgo.ECDSA_192,
                    CryptoAlgo.ECDSA_224,
                    CryptoAlgo.ECDSA_256,
//                    CryptoAlgo.ECDSA_25519,   wait for 25519 support
                    CryptoAlgo.ECDSA_384,
                    CryptoAlgo.ECDSA_521);
//            add(popupMenu, ECDSA, 192, 224, 256, CURVE_25519, 384, 521);
        }
        
        private void add(JPopupMenu popupMenu, String family, String... algos) {
            JMenu menu = new JMenu(family);
            popupMenu.add(menu);
            for (String algo : algos)
                menu.add(new SignOption(algo));
        }

        public void actionPerformed(ActionEvent event) {
            popupMenu.show((JComponent) event.getSource(), 10, 10);
        }
    }
    
    private class SignOption
            extends JMenuItem {
        SignOption(final String algo) {
            super(shortText(algo));
            addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    selectedSignAlgo = algo;
                    signAlgo.setText(algo);
                }
            });
        }
    }
    
    private class EncryptSelectionAction
            implements ActionListener {
        private final JPopupMenu popupMenu;

        EncryptSelectionAction() {
            popupMenu = new JPopupMenu("encrypt");
//            add(popupMenu, RSA, 1024, 2048, 3072, 4096);
            add(popupMenu, RSA,
                    CryptoAlgo.RSA_1024,
                    CryptoAlgo.RSA_2048,
                    CryptoAlgo.RSA_3072,
                    CryptoAlgo.RSA_4096);

//            add(popupMenu, ELGAMAL_IETF, 1024, 1536, 2048, 3072, 4096);
            add(popupMenu, ELGAMAL_IETF,
                    CryptoAlgo.IETF_1024,
                    CryptoAlgo.IETF_1536,
                    CryptoAlgo.IETF_2048,
                    CryptoAlgo.IETF_3072,
                    CryptoAlgo.IETF_4096);

//            add(popupMenu, ELGAMAL_GNUPG, 1024, 1536, 2048, 3072, 4096);
            add(popupMenu, ELGAMAL_GNUPG,
                    CryptoAlgo.GPG_1024,
                    CryptoAlgo.GPG_1536,
                    CryptoAlgo.GPG_2048,
                    CryptoAlgo.GPG_3072,
                    CryptoAlgo.GPG_4096);

//            add(popupMenu, ELGAMAL, 1024, 1536, 2048, 3072, 4096);
            add(popupMenu, ELGAMAL,
                    CryptoAlgo.ELG_1024,
                    CryptoAlgo.ELG_1536,
                    CryptoAlgo.ELG_2048,
                    CryptoAlgo.ELG_3072,
                    CryptoAlgo.ELG_4096);

            // NIST FIPS-PUB 186-4 July 2013
//          "B-163", "B-233", "B-283", "B-409", "B-571"
//          "K-163", "K-233", "K-283", "K-409", "K-571"
//          "P-192", "P-224", "P-256", "P-384", "P-521"
//            add(popupMenu, ECDH, 192, 224, 256, 384, 521);
            add(popupMenu, ECDH,
                    CryptoAlgo.ECDH_192,
                    CryptoAlgo.ECDH_224,
                    CryptoAlgo.ECDH_256,
//                    CryptoAlgo.ECDH_25519,    wait for 25519 support
                    CryptoAlgo.ECDH_384,
                    CryptoAlgo.ECDH_521);
        }

        private void add(JPopupMenu popupMenu, String family, String... algos) {
            JMenu menu = new JMenu(family);
            popupMenu.add(menu);
            for (String algo : algos)
                menu.add(new EncryptOption(algo));
        }

        public void actionPerformed(ActionEvent event) {
            if (encrypt.isSelected())
                popupMenu.show((JComponent) event.getSource(), 10, 10);
        }
    }

    private class EncryptOption
            extends JMenuItem {
        EncryptOption(final String algo) {
            super(shortText(algo));
            addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    selectedEncryptAlgo = algo;
                    encryptAlgo.setText(algo);
                }
            });
        }
    }

    private static String shortText(String algo) {
        try {
            int dotdot= algo.indexOf(':');
            return algo.substring(dotdot+1).trim();
        } catch (Exception e) {
            return algo;
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
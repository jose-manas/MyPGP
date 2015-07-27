package gui;

import javax.swing.*;
import javax.swing.plaf.basic.BasicArrowButton;
import javax.swing.text.DefaultHighlighter;
import javax.swing.text.Highlighter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

/**
 * Display a message where you can search for a pattern.
 *
 * @author Jose A. Manas
 * @version 3.1.2015
 */
public class MyTextArea {
    private static JTextArea area;
    private static String text;
    private static final JTextField patternField = new JTextField(40);
    private static int lastPosition;

    public static void show(String message, Window parent) {
        text = message.toLowerCase();
        area = new JTextArea();
        area.setText(message);
        area.setEditable(false);
        lastPosition = 0;

        JPanel findPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton backButton = new BasicArrowButton(BasicArrowButton.NORTH);
        JButton forwButton = new BasicArrowButton(BasicArrowButton.SOUTH);
        findPanel.add(patternField);
        findPanel.add(backButton);
        findPanel.add(forwButton);

        patternField.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent event) {
                forward();
            }
        });
        backButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent event) {
                backward();
            }
        });
        forwButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent event) {
                forward();
            }
        });

        Dimension screen = Toolkit.getDefaultToolkit().getScreenSize();

        JDialog dialog = new JDialog(parent, String.format("%s & %s", Text.get("files"), Text.get("keys")));
        dialog.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        dialog.getContentPane().add(new JScrollPane(area), BorderLayout.CENTER);
        dialog.getContentPane().add(findPanel, BorderLayout.SOUTH);
        dialog.setSize(screen.width / 2, screen.height / 2);
        dialog.setLocation(screen.width / 2 - dialog.getWidth() / 2,
                screen.height / 2 - dialog.getHeight() / 2);
        dialog.setVisible(true);
    }

    private static void forward() {
        try {
            Highlighter hl = area.getHighlighter();
            hl.removeAllHighlights();
            String pattern = patternField.getText().toLowerCase();
            if (pattern.length() == 0)
                return;
            int nextPosition = nextIndex(text, pattern, lastPosition + 1);
            if (nextPosition >= 0) {
                area.setSelectionStart(nextPosition);
                area.setSelectionEnd(nextPosition + pattern.length());
                hl.addHighlight(nextPosition, nextPosition + pattern.length(),
                        DefaultHighlighter.DefaultPainter);
            }
            lastPosition = nextPosition;
        } catch (Exception ignored) {
        }
    }

    private static void backward() {
        try {
            Highlighter hl = area.getHighlighter();
            hl.removeAllHighlights();
            String pattern = patternField.getText().toLowerCase();
            if (pattern.length() == 0)
                return;
            int prevPosition = prevIndex(text, pattern, lastPosition - 1);
            if (prevPosition >= 0) {
                area.setSelectionStart(prevPosition);
                area.setSelectionEnd(prevPosition + pattern.length());
                hl.addHighlight(prevPosition, prevPosition + pattern.length(),
                        DefaultHighlighter.DefaultPainter);
            }
            lastPosition = prevPosition;
        } catch (Exception ignored) {
        }
    }

    /**
     * returns next position of pattern in text - forward search + wrap
     *
     * @param text       the string to search
     * @param pattern    the string to find
     * @param startIndex the character position to start the search
     * @return next index position of start of found text or -1
     */
    public static int nextIndex(String text, String pattern, int startIndex) {
        if (text == null || pattern == null)
            return -1;
        if (text.length() < pattern.length())
            return -1;
        int index = -1;
        if (startIndex < text.length())
            index = text.indexOf(pattern, startIndex);
        if (index < 0)
            index = text.indexOf(pattern);
        return index;
    }

    /**
     * returns previous position of pattern in text - backward search + wrap
     *
     * @param text       the string to search
     * @param pattern    the string to find
     * @param startIndex the character position to start the search
     * @return previous index position of start of found text or -1
     */
    public static int prevIndex(String text, String pattern, int startIndex) {
        if (text == null || pattern == null)
            return -1;
        if (text.length() < pattern.length())
            return -1;
        int index = -1;
        if (startIndex < text.length())
            index = text.lastIndexOf(pattern, startIndex);
        if (index < 0)
            index = text.lastIndexOf(pattern);
        return index;
    }
}

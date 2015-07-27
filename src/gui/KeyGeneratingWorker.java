package gui;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

/**
 * Wraps key generation to be executed in the background.
 *
 * @author Jose A. Manas
 * @version 20.8.2014
 */
public class KeyGeneratingWorker
        extends SwingWorker<Void, String> {
    private final static SimpleDateFormat timerFormat = new SimpleDateFormat("  mm : ss  ");

    private KeyGeneratingThread task;

    private JDialog frame;
    private JProgressBar progressBar;
    private final MyPGP myPGP;

    public KeyGeneratingWorker(MyPGP myPGP, KeyGeneratingThread task) {
        this.myPGP = myPGP;
        this.task = task;

        frame = new JDialog(myPGP.getWindow(), Text.get("wait"));
        frame.setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
        frame.setBackground(Color.WHITE);
        frame.addWindowListener(new WindowListener());

        Container contentPane = frame.getContentPane();

        progressBar = new JProgressBar(0, 100);
        progressBar.setIndeterminate(true);
        progressBar.setStringPainted(true);
        progressBar.setString("");
        contentPane.add(progressBar, BorderLayout.CENTER);

        JButton cancelButton = new JButton(Text.get("cancel"));
        cancelButton.addActionListener(new CancelActionListener());
        contentPane.add(cancelButton, BorderLayout.SOUTH);

        frame.pack();
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
    }

    @Override
    protected Void doInBackground() {
        task.start();
        final long startTime = System.currentTimeMillis();
        while (task.isAlive()) {
            long elapsedTime = System.currentTimeMillis() - startTime;
            publish(timerFormat.format(new Date(elapsedTime)));
            try {
                Thread.sleep(1000);
            } catch (InterruptedException ignored) {
            }
        }
        return null;
    }

    @Override
    protected void process(List<String> chunks) {
        for (String chunk : chunks)
            progressBar.setString(chunk);
    }

    @Override
    protected void done() {
        frame.dispose();
        myPGP.keyGenerated(task);
    }

    private class CancelActionListener
            implements ActionListener {
        public void actionPerformed(ActionEvent event) {
            task.interrupt();
        }
    }

    private class WindowListener
            extends WindowAdapter {
        @Override
        public void windowClosing(WindowEvent event) {
            task.interrupt();
        }
    }
}

package gui;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.RandomAccessFile;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

/**
 * Wraps file wiping to be executed in the background.
 *
 * @author Jose A. Manas
 * @version 20.8.2014
 */
public class SecureDeleteWorker
        extends SwingWorker<Void, Long> {
    private final File file;
    private long length;

    private JDialog frame;
    private JProgressBar progressBar;
    private Exception executonException;

    public SecureDeleteWorker(File file) {
        this.file = file;
        length = file.length();

        frame = new JDialog(MyPGP.getWindow(), Text.get("wait"));
        frame.setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
        frame.setBackground(Color.WHITE);

        Container contentPane = frame.getContentPane();

        progressBar = new JProgressBar(0, (int) (3 * length));
        progressBar.setStringPainted(true);
        progressBar.setValue(0);
        contentPane.add(progressBar, BorderLayout.CENTER);

        frame.pack();
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
    }

    @Override
    protected Void doInBackground() {
        int chunk = 128 * 1024;
        try {
            SecureRandom random = new SecureRandom();
            RandomAccessFile raf = new RandomAccessFile(file, "rws");
//            byte mask = (byte) 0;
            byte mask = (byte) 0xC1;    // CCN-STIC 404
            byte[] data = new byte[chunk];

            {
                Arrays.fill(data, mask);
                raf.seek(0);
                raf.getFilePointer();
                long pos = 0;
                while (pos < length) {
                    int n = (int) Math.min(chunk, length - pos);
                    raf.write(data, 0, n);
                    pos += n;
                    publish(pos);
                }
            }
            {
                Arrays.fill(data, (byte) ~mask);
                raf.seek(0);
                raf.getFilePointer();
                long pos = 0;
                while (pos < length) {
                    int n = (int) Math.min(chunk, length - pos);
                    raf.write(data, 0, n);
                    pos += n;
                    publish(length + pos);
                }
            }
            {
                raf.seek(0);
                raf.getFilePointer();
                long pos = 0;
                while (pos < length) {
                    random.nextBytes(data);
                    int n = (int) Math.min(chunk, length - pos);
                    raf.write(data, 0, n);
                    pos += n;
                    publish(2 * length + pos);
                }
            }

            raf.close();
            file.delete();
        } catch (Exception e) {
            executonException = e;
        }
        return null;
    }

    @Override
    protected void process(List<Long> chunks) {
        for (long chunk : chunks)
            progressBar.setValue((int) chunk);
    }

    @Override
    protected void done() {
        frame.dispose();
        MyPGP.fileDeleted(this);
    }

    Exception getExecutonException() {
        return executonException;
    }
}

package gui;

import gui.imgs.Icons;

import javax.swing.*;
import java.awt.*;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * @author Jose A. Manas
 * @version 10.6.2011
 */
public class StopWatch
        extends Thread {
    private final static SimpleDateFormat timerFormat = new SimpleDateFormat("  mm : ss  ");

    private volatile boolean isRunning;

    private JFrame frame;
    private JLabel counter;

    public StopWatch() {
        frame = new JFrame(Text.get("wait"));
        frame.setIconImage(Icons.getPgpImage());
        frame.setDefaultCloseOperation(JFrame.HIDE_ON_CLOSE);
        frame.setBackground(Color.WHITE);
        counter = new JLabel();
        counter.setFont(new Font("Courier New", Font.ITALIC, 20));
        counter.setOpaque(true);
        counter.setBackground(Color.WHITE);
        counter.setText(timerFormat.format(new Date((long) 0)));
        frame.getContentPane().add(counter, BorderLayout.CENTER);
        frame.setSize(200, 80);
        frame.setLocationRelativeTo(null);
    }

    @Override
    public void run() {
        final long startTime = System.currentTimeMillis();
        isRunning = true;
        boolean visible = false;
        while (isRunning) {
            long elapsedTime = System.currentTimeMillis() - startTime;
            if (elapsedTime < 2500)
                continue;
            if (!visible) {
                frame.setVisible(true);
                visible = true;
            }
            counter.setText(timerFormat.format(new Date(elapsedTime)));
            counter.paintImmediately(counter.getBounds());
            try {
                Thread.sleep(1000);
            } catch (InterruptedException ignored) {
            }
        }
        frame.dispose();
    }

    public void die() {
        isRunning = false;
    }

    public static void main(String[] arg) {
        StopWatch watch = new StopWatch();
        watch.start();
        try {
            Thread.sleep(30000);
        } catch (InterruptedException ignored) {
        }
        watch.die();
    }
}


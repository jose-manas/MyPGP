package bc;

import exception.MyLogger;
import gui.Text;

import java.io.*;
import java.util.Iterator;

public class PemSplitter
        implements Iterator<InputStream> {
    public static final int CR = 0x0d;
    public static final int LF = 0x0a;

    private static final String BEGIN_PGP = "-----BEGIN PGP ";
    private static final String END_PGP = "-----END PGP ";

    private final BufferedReader reader;
    private String nextLine;
    private InputStream binaryToRead;
    private InputStream binaryToClose;

    public PemSplitter(File child)
            throws IOException {
        InputStream is = new FileInputStream(child);
        reader = new BufferedReader(new InputStreamReader(is));
        findNext();
        if (nextLine == null) {
            reader.close();
            binaryToRead = new FileInputStream(child);
            binaryToClose = binaryToRead;
        }
    }

    public void close() {
        try {
            if (binaryToClose != null)
                binaryToClose.close();
            else if (reader != null)
                reader.close();
        } catch (Exception e) {
            MyLogger.dump(e, Text.get("keys"));
        }
    }

    private void findNext() {
        if (binaryToRead != null)
            return;

        for (; ; ) {
            try {
                nextLine = reader.readLine();
            } catch (IOException e) {
                nextLine = null;
            }
            if (nextLine == null)
                break;
//            if (nextLine.length() > 0) {
//                char ch = nextLine.charAt(nextLine.length() - 1);
//                if (ch == CR || ch == LF)
//                    System.out.println(nextLine);
//            }
            if (nextLine.length() < BEGIN_PGP.length())
                continue;
            if (nextLine.substring(0, BEGIN_PGP.length()).equalsIgnoreCase(BEGIN_PGP))
                break;
        }
    }

    public boolean hasNext() {
        return nextLine != null || binaryToRead != null;
    }

    public InputStream next() {
        if (!hasNext())
            return null;
        if (binaryToRead != null) {
            InputStream is = binaryToRead;
            binaryToRead = null;
            return is;
        }
        if (nextLine == null)
            return null;

        // read to end
        StringBuilder lines = new StringBuilder();
        lines.append(nextLine).append('\n');

        for (; ; ) {
            try {
                nextLine = reader.readLine();
            } catch (IOException e) {
                nextLine = null;
            }
            if (nextLine == null)
                break;
            lines.append(nextLine).append('\n');
            if (nextLine.length() < END_PGP.length())
                continue;
            if (nextLine.substring(0, END_PGP.length()).equalsIgnoreCase(END_PGP))
                break;
        }

        findNext();
        return new ByteArrayInputStream(lines.toString().getBytes());
    }

    public void remove() {
        throw new UnsupportedOperationException();
    }

    public static void main(String[] args)
            throws IOException {
        PemSplitter splitter = new PemSplitter(new File(args[0]));
        while (splitter.hasNext()) {
            InputStream is = splitter.next();
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(is));
            String line = bufferedReader.readLine();
            System.out.println(line);
        }
        splitter.close();
    }
}

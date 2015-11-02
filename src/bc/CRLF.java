package bc;

import java.io.*;

/**
 * InputStream filter to deal with CR-LF problems in poorly formatted files.
 *
 * @author Jose A. Manas
 * @version 16.5.2011
 */
public class CRLF {
    private static final String BEGIN_PGP = "-----BEGIN PGP ";
    private static final String END_PGP = "-----END PGP ";

    private static final int READ_AHEAD = 200;

    public static void main(String[] args)
            throws IOException {
        InputStream in1 = new FileInputStream(args[0]);
        InputStream in2 = sanitize(in1);

        OutputStream out = new FileOutputStream("out_" + args[0]);
        for (; ; ) {
            int ch = in2.read();
            if (ch < 0)
                break;
            out.write(ch);
        }
        in1.close();
        out.close();
    }

    // email interfaces play with lines in html format and may confuse b64 parser
    // first, let's decide whether it is binary of asc armored
    public static InputStream sanitize(InputStream in)
            throws IOException {
        BufferedInputStream bif = new BufferedInputStream(in);
        bif.mark(READ_AHEAD);
        byte[] bytes = new byte[READ_AHEAD];
        int n = bif.read(bytes);
        String ascii7 = new String(bytes, 0, n);
        if (ascii7.contains(BEGIN_PGP)) {
            // ASC
            bif.reset();
            return clean(bif);
        } else {
            // binary
            bif.reset();
            return bif;
        }
    }

    // asc armor; let's simplify ends of line
    // respect one empty line between armor headers and body
    private static InputStream clean(InputStream in)
            throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintStream out = new PrintStream(baos);
        BufferedReader br = new BufferedReader(new InputStreamReader(in));

        // 0 - waiting for header
        // 1 - reading headers
        // 2 - reading body
        int state = 0;
        for (; ; ) {
            String line = br.readLine();
            if (line == null)
                break;
            line = line.trim();
            switch (state) {
                case 0:
                    if (line.startsWith(BEGIN_PGP)) {
                        out.println(line);
                        state = 1;
                    }
                    continue;
                case 1:
                    if (line.length() == 0)
                        continue;
                    if (!line.contains(": ")) {
                        out.println();
                        state = 2;
                    }
                    out.println(line);
                    continue;
                case 2:
                    if (line.length() == 0)
                        continue;
                    if (line.startsWith(END_PGP)) {
                        out.println(line);
                        state = 0;
                    } else {
                        out.println(line);
                    }
            }
        }
        in.close();
        out.close();

/*
        BufferedReader check =
                new BufferedReader(
                        new InputStreamReader(
                                new ByteArrayInputStream(baos.toByteArray())));
        for (; ; ) {
            String line = check.readLine();
            if (line == null)
                break;
            System.out.println(line);
        }
        check.close();
*/

        return new ByteArrayInputStream(baos.toByteArray());
    }
}

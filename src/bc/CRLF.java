package bc;

import java.io.*;

/**
 * InputStream filter to deal with CR-LF problems in poorly formatted files.
 *
 * @author Jose A. Manas
 * @version 16.5.2011
 */
public class CRLF {
    public static final int READ_AHEAD = 200;
    public static final int CR = 0x0d;
    public static final int LF = 0x0a;

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

    public static InputStream sanitize(InputStream in)
            throws IOException {
        BufferedInputStream bif = new BufferedInputStream(in);
        bif.mark(READ_AHEAD);
        byte[] bytes = new byte[READ_AHEAD];
        int n = bif.read(bytes);
        for (int i = 0; i < n - 2; i++) {
            byte b = bytes[i];
            if ((b & 0x80) != 0)
                break;
            byte b0 = bytes[i];
            byte b1 = bytes[i + 1];
            byte b2 = bytes[i + 2];
            if (b0 == CR && b1 == CR && b2 == LF) {
//                System.out.printf("%d: %02x%02x%02x%n", i, b0, b1, b2);
                bif.reset();
                return clean(bif);
            }
        }
//        System.out.println("binary");
        bif.reset();
        return bif;
    }

    private static InputStream clean(InputStream in)
            throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int state = 0;
        for (; ; ) {
            int ch = in.read();
            if (ch < 0)
                break;
            switch (state) {
                case 0:
                    if (ch == CR)
                        state = 1;
                    else
                        baos.write(ch);
                    break;
                case 1:
                    if (ch == CR) {
                        state = 2;
                    } else {
                        baos.write(CR);
                        baos.write(ch);
                        state = 0;
                    }
                    break;
                case 2:
                    if (ch == LF) {
                        baos.write(CR);
                        baos.write(LF);
                    } else {
                        baos.write(CR);
                        baos.write(CR);
                        baos.write(ch);
                    }
                    state = 0;
            }
        }
        in.close();

        if (state == 1) {
            baos.write(CR);
        } else if (state == 2) {
            baos.write(CR);
            baos.write(CR);
        }
        baos.close();
        return new ByteArrayInputStream(baos.toByteArray());
    }
}

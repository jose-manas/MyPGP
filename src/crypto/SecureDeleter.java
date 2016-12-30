package crypto;

import gui.MyPGP;
import gui.SecureDeleteWorker;

import java.io.File;

/**
 * @author Jose A. Manas
 * @version 13.5.2011
 */
public class SecureDeleter {
    public static void delete(MyPGP myPGP, File file) {
        if (!file.exists())
            return;
        if (file.isDirectory()) {
            File[] files = file.listFiles();
            if (files != null) {
                for (File f : files)
                    delete(myPGP, f);
            }
            file.delete();
        } else {
            SecureDeleteWorker worker = new SecureDeleteWorker(myPGP, file);
            worker.execute();
        }
    }
}

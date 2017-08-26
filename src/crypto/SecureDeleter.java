package crypto;

import gui.SecureDeleteWorker;

import java.io.File;

/**
 * @author Jose A. Manas
 * @version 13.5.2011
 */
public class SecureDeleter {
    public static void delete(File file) {
        if (!file.exists())
            return;
        if (file.isDirectory()) {
            File[] files = file.listFiles();
            if (files != null) {
                for (File f : files)
                    delete(f);
            }
            file.delete();
        } else {
            SecureDeleteWorker worker = new SecureDeleteWorker(file);
            worker.execute();
        }
    }
}

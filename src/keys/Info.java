package keys;

import exception.MyLogger;
import gui.Text;

import java.io.*;
import java.util.prefs.Preferences;

/**
 * @author Jose A. Manas
 * @version 1.6.2011
 */
public class Info {
    //    public static final String CONFIGURATION_MYPGP = "configuration.mypgp";
    private static final String DATABASE_MYPGP = "database.mypgp";

    private static final Preferences preferences =
            Preferences.userRoot().node("mypgp");

    private static File home;

    public static void setHome(File home) {
        Info.home = home;
    }

    public static void loadInfo() {
        BufferedReader reader = null;
        try {
            File database = new File(getHome(), DATABASE_MYPGP);
            if (!database.exists())
                return;
            InputStream is = new FileInputStream(database);
            reader = new BufferedReader(new InputStreamReader(is, "UTF-8"));
            for (; ; ) {
                String line = reader.readLine();
                if (line == null)
                    break;
                if (line.startsWith("alias."))
                    loadAlias(line);
                else if (line.startsWith("list."))
                    loadList(line);
            }
        } catch (Exception e) {
            MyLogger.dump(e, "load: alias.");
        } finally {
            try {
                if (reader != null)
                    reader.close();
            } catch (IOException ignored) {
            }
        }
    }

    private static void loadAlias(String line) {
        int dot = "alias.".length();
        int eq = line.indexOf('=');
        if (eq > 0)
            KeyDB2.setAlias(line.substring(dot, eq).trim(), line.substring(eq + 1).trim());
    }

    private static void loadList(String line) {
        try {
            int eq = line.indexOf('=');
            if (eq < 0)
                return;
            String[] s = line.substring(0, eq).split("\\.");
            if (s.length != 3)
                return;
            if (!s[0].equalsIgnoreCase("list"))
                return;
            int uid = Integer.parseInt(s[1]);
            KeyList list = KeyListDB.get(uid);
            if (list == null) {
                list = new KeyList(uid, "");
                KeyListDB.add(list);
            }
            if (s[2].equalsIgnoreCase("name"))
                list.setName(line.substring(eq + 1).trim());
            if (s[2].equalsIgnoreCase("members"))
                list.load(line.substring(eq + 1).trim());
        } catch (Exception e) {
            MyLogger.dump(e, "loading ");
        }
    }

    public static void saveInfo() {
        PrintWriter writer = null;
        try {
            File configuration = new File(home, DATABASE_MYPGP);
            OutputStream os = new FileOutputStream(configuration);
            writer = new PrintWriter(new OutputStreamWriter(os, "UTF-8"));
            KeyDB2.saveKeys(writer);
            KeyListDB.saveLists(writer);
        } catch (Exception e) {
            MyLogger.dump(e, "save info");
        } finally {
            if (writer != null)
                writer.close();
        }
    }

    public static File getHome() {
        return home;
    }

    public static void saveLanguage() {
        preferences.put("language", Text.getLocale().getLanguage());
    }

}

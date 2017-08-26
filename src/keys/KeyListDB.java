package keys;

import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

// 29.6.2011 clear before reloading
// 24.8.2017 remove singleton architecture

/**
 * @author Jose A. Manas
 * @version 1.6.2011
 */
public class KeyListDB {
    private static Map<Integer, KeyList> uidMap = new HashMap<Integer, KeyList>();
    private static Set<KeyList> listSet = new TreeSet<KeyList>();

    public static KeyList get(int uid) {
        return uidMap.get(uid);
    }

    public static KeyList get(String name) {
        for (KeyList list : uidMap.values()) {
            if (list.getName().equalsIgnoreCase(name))
                return list;
        }
        return null;
    }

    public static void clear() {
        uidMap.clear();
        listSet.clear();
    }

    public static void add(KeyList list) {
        uidMap.put(list.getUid(), list);
        listSet.clear();
    }

    public static void removeList(KeyList list) {
        uidMap.remove(list.getUid());
        listSet.clear();
    }

    public static void removeKey(Key key) {
        for (KeyList list : uidMap.values())
            list.remove(key);
    }

    static void saveLists(PrintWriter writer) {
        for (KeyList list : uidMap.values())
            list.save(writer);
    }

    public static Set<KeyList> getListSet() {
        if (listSet.isEmpty())
            listSet.addAll(uidMap.values());
        return listSet;
    }
}

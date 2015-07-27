package keys;

import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

// 29.6.2011 clear before reloading

/**
 * @author Jose A. Manas
 * @version 1.6.2011
 */
public class KeyListDB {
    private static KeyListDB instance = new KeyListDB();

    public static KeyListDB getInstance() {
        return instance;
    }

    private Map<Integer, KeyList> uidMap = new HashMap<Integer, KeyList>();
    private Set<KeyList> listSet = new TreeSet<KeyList>();

    public KeyList get(int uid) {
        return uidMap.get(uid);
    }

    public KeyList get(String name) {
        for (KeyList list : uidMap.values()) {
            if (list.getName().equalsIgnoreCase(name))
                return list;
        }
        return null;
    }

    public void clear() {
        uidMap.clear();
        listSet.clear();
    }

    public void add(KeyList list) {
        uidMap.put(list.getUid(), list);
        listSet.clear();
    }

    public void removeList(KeyList list) {
        uidMap.remove(list.getUid());
        listSet.clear();
    }

    public void removeKey(Key key) {
        for (KeyList list : uidMap.values())
            list.remove(key);
    }

    public void saveLists(PrintWriter writer) {
        for (KeyList list : uidMap.values())
            list.save(writer);
    }

    public Set<KeyList> getListSet() {
        if (listSet.isEmpty())
            listSet.addAll(uidMap.values());
        return listSet;
    }
}

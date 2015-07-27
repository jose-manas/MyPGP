package bc;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;

/**
 * Useful class for dynamically changing the classpath, adding classes during runtime.
 * <p/>
 * http://stackoverflow.com/questions/60764/how-should-i-load-jars-dynamically-at-runtime
 */
public class ClasspathHacker {
    /**
     * Parameters of the method to add an URL to the System classes.
     */
    private static final Class<?>[] parameters = new Class[]{URL.class};

    /**
     * Adds a file to the classpath.
     *
     * @param filename a String pointing to the file
     * @throws IOException
     */
    public static void addFile(String filename)
            throws IOException {
        System.err.println("ClasspathHacker.addFile() " + filename);
        addFile(new File(filename));
    }

    /**
     * Adds a file to the classpath
     *
     * @param file the file to be added
     * @throws IOException
     */
    public static void addFile(File file)
            throws IOException {
        addURL(file.toURI().toURL());
    }

    /**
     * Adds the content pointed by the URL to the classpath.
     *
     * @param url the URL pointing to the content to be added
     * @throws IOException
     */
    public static void addURL(URL url)
            throws IOException {
        URLClassLoader sysloader = (URLClassLoader) ClassLoader.getSystemClassLoader();
        Class<?> sysclass = URLClassLoader.class;
        try {
            Method method = sysclass.getDeclaredMethod("addURL", parameters);
            method.setAccessible(true);
            method.invoke(sysloader, url);
        } catch (Throwable t) {
//            t.printStackTrace();
            throw new IOException("Error, could not add URL to system classloader");
        }
    }
}
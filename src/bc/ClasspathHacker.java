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
     * Adds the content pointed by the URL to the classpath.
     *
     * @param url the URL pointing to the content to be added
     * @throws IOException
     */
    public static void addURL(URL url)
            throws IOException {
//        URLClassLoader sysloader = (URLClassLoader) ClassLoader.getSystemClassLoader();
        URLClassLoader sysloader = new URLClassLoader(new URL[]{url});
        Class<?> sysclass = URLClassLoader.class;
        try {
            Method method = sysclass.getDeclaredMethod("addURL", parameters);
            method.setAccessible(true);
            method.invoke(sysloader, url);
        } catch (Throwable t) {
            throw new IOException("Error, could not add URL to system classloader");
        }
    }

    public static void addFiles8(File[] files) throws IOException {
        try {
            for (File file : files) {
                URL url = file.toURI().toURL();
                URLClassLoader sysloader = (URLClassLoader) ClassLoader.getSystemClassLoader();
                Class<?> sysclass = URLClassLoader.class;
                Method method = sysclass.getDeclaredMethod("addURL", parameters);
                method.setAccessible(true);
                method.invoke(sysloader, url);
            }
        } catch (Throwable t) {
            throw new IOException("Error, could not add URL to system classloader");
        }
    }

    public static void addFiles9(File[] files) throws IOException {
        try {
            for (File file : files) {
                URL url = file.toURI().toURL();
                URLClassLoader sysloader = new URLClassLoader(new URL[]{url});
                Class<?> sysclass = URLClassLoader.class;
                Method method = sysclass.getDeclaredMethod("addURL", parameters);
                method.setAccessible(true);
                method.invoke(sysloader, url);
            }
        } catch (Throwable t) {
            throw new IOException("Error, could not add URL to system classloader");
        }
    }
}
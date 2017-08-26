package bc;

import gui.MyPGP;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Security;
import java.util.Map;

/**
 * @author Jose A. Manas
 * @version 1.9.2014
 */
public class Provider {

    public static void set() {
        removeCryptographyRestrictions();
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * http://stackoverflow.com/questions/1179672/unlimited-strength-jce-policy-files
     */
    private static void removeCryptographyRestrictions() {
        try {
            /*
            * Do the following, but with reflection to bypass access checks:
            *
            * JceSecurity.isRestricted = false;
            * JceSecurity.defaultPolicy.perms.clear();
            * JceSecurity.defaultPolicy.add(CryptoAllPermission.INSTANCE);
            */
            final Class<?> jceSecurity = Class.forName("javax.crypto.JceSecurity");
            final Class<?> cryptoPermissions = Class.forName("javax.crypto.CryptoPermissions");
            final Class<?> cryptoAllPermission = Class.forName("javax.crypto.CryptoAllPermission");

            final Field isRestrictedField = jceSecurity.getDeclaredField("isRestricted");
            isRestrictedField.setAccessible(true);
            Field modifiersField = Field.class.getDeclaredField("modifiers");
            modifiersField.setAccessible(true);
            modifiersField.setInt(isRestrictedField, isRestrictedField.getModifiers() & ~Modifier.FINAL);
            isRestrictedField.set(null, false);

            final Field defaultPolicyField = jceSecurity.getDeclaredField("defaultPolicy");
            defaultPolicyField.setAccessible(true);
            final PermissionCollection defaultPolicy = (PermissionCollection) defaultPolicyField.get(null);

            final Field perms = cryptoPermissions.getDeclaredField("perms");
            perms.setAccessible(true);
            Map<?, ?> map = (Map<?, ?>) perms.get(defaultPolicy);
            map.clear();

            final Field instance = cryptoAllPermission.getDeclaredField("INSTANCE");
            instance.setAccessible(true);
            defaultPolicy.add((Permission) instance.get(null));

//            MyPGP.log("Successfully removed cryptography restrictions");
        } catch (final Exception e) {
            MyPGP.log("Failed to remove cryptography restrictions: " + e);
        }
    }

}

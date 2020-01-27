package gui;

import exception.MyLogger;

import java.util.Locale;
import java.util.Properties;

/**
 * Language dependant texts without external dictionary.
 *
 * @author Jose A. Manas
 * @version 30.12.2016
 */
public class Text {
    private static Locale locale;
    private static final Properties dictionary = new Properties();

    private static final String[][] languages = {
            {"en", "English"},
            {"es", "Espa\u00F1ol"},
    };

    static String[][] getLanguages() {
        return languages;
    }

    public static String get(String key) {
        String text = dictionary.getProperty(key);
        if (text == null)
            return key;
        return text;
    }

    static void setLocale(String lang) {
        try {
            Text.locale = new Locale(lang);
            setDefaults();
        } catch (Exception e) {
            MyLogger.dump(e, lang);
        }
    }

    public static Locale getLocale() {
        return locale;
    }

    private static void setDefaults() {
        Locale.setDefault(locale);
        if (locale.getLanguage().startsWith("es"))
            setES();
        else
            setEN();
    }

    private static void setEN() {
        dictionary.put("accept", "accept");
        dictionary.put("add_key_list", "add key(s) to list(s)");
        dictionary.put("add_key_sig", "sign key");
        dictionary.put("algorithms", "algorithms");
        dictionary.put("alias", "alias");
        dictionary.put("binary", "binary");
        dictionary.put("cancel", "cancel");
        dictionary.put("clipboard", "clipboard");
        dictionary.put("comment", "comment");
        dictionary.put("confirm", "confirm");
        dictionary.put("copy", "copy");
        dictionary.put("date", "date");
        dictionary.put("decrypt", "decrypt");
        dictionary.put("decrypt_verify", "decrypt & verify");
        dictionary.put("delete", "secure delete");
        dictionary.put("delete?", "delete forever?");
        dictionary.put("del_key_sig", "remove signature");
        dictionary.put("email", "email");
        dictionary.put("encrypt", "encrypt");
        dictionary.put("encrypt_sign", "encrypt & sign");
        dictionary.put("encrypted_for", "encrypted for");
        dictionary.put("exception", "exception");
        dictionary.put("exception.bad_format", "bad format");
        dictionary.put("exception.password_cancelled", "password cancelled");
        dictionary.put("exception.password_needed", "password needed");
        dictionary.put("expire", "expire");
        dictionary.put("export", "export");
        dictionary.put("filename", "filename");
        dictionary.put("files", "files");
        dictionary.put("find", "find");
        dictionary.put("fingerprint", "fingerprint");
        dictionary.put("generate", "new key");
        dictionary.put("import", "import");
        dictionary.put("key_directory", "key directory");
        dictionary.put("keys", "keys");
        dictionary.put("language", "language");
        dictionary.put("lists", "lists");
        dictionary.put("name", "name");
        dictionary.put("new", "new");
        dictionary.put("new_directory", "new directory");
        dictionary.put("new_list", "new list");
        dictionary.put("no_known_key", "no known key");
        dictionary.put("no_libraries", "libraries no found (jar)");
        dictionary.put("no_signed_file", "no signed file");
        dictionary.put("overwrite", "overwrite");
        dictionary.put("password", "password");
        dictionary.put("process", "process");
        dictionary.put("public_keys", "public keys (decrypt | verify signature)");
        dictionary.put("refresh", "refresh");
        dictionary.put("remove", "remove");
        dictionary.put("remove_key_list", "remove key(s) from list(s)");
        dictionary.put("remove_list", "remove list(s)");
        dictionary.put("secret_keys", "secret keys (decrypt | sign)");
        dictionary.put("select_directory", "select a directory");
        dictionary.put("sign", "sign");
        dictionary.put("signature", "signature");
        dictionary.put("signature_bad", "signature fails");
        dictionary.put("signature_ok", "signature ok");
        dictionary.put("signer", "signer");
        dictionary.put("signers", "endorsed by");
        dictionary.put("signers_none", "no signers");
        dictionary.put("size", "size");
        dictionary.put("skip", "skip");
        dictionary.put("text", "text");
        dictionary.put("unknown", "unknown");
        dictionary.put("verify", "verify");
        dictionary.put("wait", "wait ...");
        dictionary.put("view", "view");
    }

    private static void setES() {
        dictionary.put("accept", "aceptar");
        dictionary.put("add_key_list", "a\u00F1adir clave(s) a lista(s)");
        dictionary.put("add_key_sig", "firmar clave");
        dictionary.put("algorithms", "algoritmos");
        dictionary.put("alias", "alias");
        dictionary.put("binary", "binario");
        dictionary.put("cancel", "cancelar");
        dictionary.put("clipboard", "portapapeles");
        dictionary.put("comment", "comentario");
        dictionary.put("confirm", "confirmar");
        dictionary.put("copy", "copiar");
        dictionary.put("date", "fecha");
        dictionary.put("decrypt", "descifrar");
        dictionary.put("decrypt_verify", "descifrar y verificar");
        dictionary.put("delete", "borrado seguro");
        dictionary.put("delete?", "\u00BFborrar para siempre?");
        dictionary.put("del_key_sig", "eliminar firma");
        dictionary.put("email", "email");
        dictionary.put("encrypt", "cifrar");
        dictionary.put("encrypt_sign", "cifrar y firmar");
        dictionary.put("encrypted_for", "cifrado para");
        dictionary.put("exception", "excepci\u00F3n");
        dictionary.put("exception.bad_format", "formato incorrecto");
        dictionary.put("exception.password_cancelled", "contrase\u00F1a cancelada");
        dictionary.put("exception.password_needed", "se requiere una contrase\u00F1a");
        dictionary.put("expire", "expira");
        dictionary.put("export", "exportar");
        dictionary.put("filename", "fichero");
        dictionary.put("files", "ficheros");
        dictionary.put("fingerprint", "huella");
        dictionary.put("find", "buscar");
        dictionary.put("generate", "nueva clave");
        dictionary.put("import", "importar");
        dictionary.put("key_directory", "directorio de claves");
        dictionary.put("keys", "claves");
        dictionary.put("language", "idioma");
        dictionary.put("lists", "listas");
        dictionary.put("name", "nombre");
        dictionary.put("new", "nuevo");
        dictionary.put("new_directory", "nuevo directorio");
        dictionary.put("new_list", "nueva lista");
        dictionary.put("no_known_key", "no hay claves conocidas");
        dictionary.put("no_libraries", "faltan las bibliotecas (jar)");
        dictionary.put("no_signed_file", "no se encuentra el fichero firmado");
        dictionary.put("overwrite", "sobreescribir");
        dictionary.put("password", "contrase\u00F1a");
        dictionary.put("process", "procesar");
        dictionary.put("public_keys", "claves p\u00FAblicas (cifrar | verificar firma)");
        dictionary.put("refresh", "refrescar");
        dictionary.put("remove", "eliminar");
        dictionary.put("remove_key_list", "eliminar clave(s) de lista(s)");
        dictionary.put("remove_list", "eliminar lista(s)");
        dictionary.put("secret_keys", "claves secretas (descrifrar | firmar)");
        dictionary.put("select_directory", "seleccione un directorio");
        dictionary.put("sign", "firmar");
        dictionary.put("signature", "firma");
        dictionary.put("signature_bad", "firma incorrecta");
        dictionary.put("signature_ok", "firma correcta");
        dictionary.put("signer", "firmado por");
        dictionary.put("signers", "avalada por");
        dictionary.put("signers_none", "no hay firmas");
        dictionary.put("size", "tama\u00F1o");
        dictionary.put("skip", "ignorar");
        dictionary.put("text", "texto");
        dictionary.put("unknown", "desconocida");
        dictionary.put("verify", "verificar");
        dictionary.put("wait", "espere ...");
        dictionary.put("view", "ver");
    }
}

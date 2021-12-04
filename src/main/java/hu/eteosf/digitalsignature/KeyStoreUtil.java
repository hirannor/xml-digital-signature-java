package hu.eteosf.digitalsignature;

import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.X509Certificate;

/**
 * Util class for java keystore to load keystore, get certificate and private key.
 *
 * @author mate.karolyi
 */
public class KeyStoreUtil {

    private static final String KEY_STORE_TYPE = "PKCS12";
    private static final String KEYSTORE = "keystore.pfx";
    private static final String KEYSTORE_ALIAS = "somealias";
    private static final char[] PASSWORD = "changeit".toCharArray();

    public static PrivateKey getPrivateKey(final KeyStore keyStore) {
        try {
            return (PrivateKey) keyStore.getKey(KEYSTORE_ALIAS, PASSWORD);
        } catch (KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException ex) {
            throw new RuntimeException("Could not get private key: ", ex);
        }
    }

    public static X509Certificate getCertificate(final KeyStore keyStore) {
        try {
            return (X509Certificate) keyStore.getCertificate(KEYSTORE_ALIAS);
        } catch (KeyStoreException ex) {
            throw new RuntimeException("Could not get certificate: ", ex);
        }
    }

    public static KeyStore loadKeyStore() {
        try {
            final KeyStore keyStore = KeyStore.getInstance(KEY_STORE_TYPE);
            final InputStream resourceAsStream = KeyStoreUtil.class.getClassLoader().getResourceAsStream(KEYSTORE);

            if (resourceAsStream == null) {
                throw new FileNotFoundException("Resource not found: " + KEYSTORE);
            }

            keyStore.load(resourceAsStream, PASSWORD);

            return keyStore;
        } catch (Exception ex) {
            throw new RuntimeException("Could not load keystore: ", ex);
        }
    }

}

package hu.signatures.samples.signandverifycommon.util;

import hu.signatures.samples.signandverifycommon.exception.SignAndVerifyException;

import java.io.FileInputStream;
import java.security.KeyStore;

public class KeystoreUtils {

    private KeystoreUtils() {
        throw new IllegalStateException("Utility class");
    }

    public static KeyStore loadKeystore(String location, String type, String password) {
        try (FileInputStream fis = new FileInputStream(location)) {
            KeyStore keyStore = KeyStore.getInstance(type);
            keyStore.load(fis, password.toCharArray());
            return keyStore;
        } catch (Exception e) {
            throw new SignAndVerifyException("Unable to load keystore", e);
        }
    }
}

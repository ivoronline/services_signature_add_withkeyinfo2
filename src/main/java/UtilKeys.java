import java.io.InputStream;
import java.security.KeyStore;

public class UtilKeys {

  //================================================================================
  // GET KEY PAIR
  //================================================================================
  public static KeyStore.PrivateKeyEntry getKeyPair(
    String keyStoreName,     //"/ClientKeyStore.jks"
    String keyStorePassword, //"mypassword";
    String keyStoreType,     //"JKS"
    String keyAlias          //"clientkeys1"
  ) throws Exception {

    //GET PRIVATE KEY
    InputStream                 inputStream = UtilKeys.class.getResourceAsStream(keyStoreName);
    char[]                      password    = keyStorePassword.toCharArray();    //For KeyStore & Private Key
    KeyStore                    keyStore    = KeyStore.getInstance(keyStoreType);
                                keyStore.load(inputStream, password);
    KeyStore.PasswordProtection keyPassword = new KeyStore.PasswordProtection(password);
    KeyStore.PrivateKeyEntry    keyPair = (KeyStore.PrivateKeyEntry) keyStore.getEntry(keyAlias, keyPassword);

    //RETURN KEY PAIR
    return keyPair;

  }

}

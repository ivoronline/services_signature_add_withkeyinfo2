import org.w3c.dom.Document;
import xmlutil.XMLUtil;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.SignatureMethod;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class AddSignature {

  //KEY STORE
  static String keyStoreName     = "src/main/resources/ClientKeyStore.jks";
  static String keyStorePassword = "mypassword";
  static String keyStoreType     = "JKS";
  static String keyAlias         = "clientkeys1";

  //XML FILES
  static String fileXMLInput     = "src/main/resources/Person.xml";
  static String fileXMLSigned    = "src/main/resources/PersonSignedWithKeyInfo.xml";

  //================================================================================
  // MAIN
  //================================================================================
  public static void main(String[] args) throws Exception {

    //GET KEYS
    KeyStore.PrivateKeyEntry keyPair    = XMLUtil.getPrivateKeyPair(keyStoreName, keyStorePassword, keyStoreType, keyAlias);
    PrivateKey               privateKey = keyPair.getPrivateKey();
    X509Certificate          certificate= (X509Certificate) keyPair.getCertificate();

    //SIGN DOCUMENT
    Document              document = XMLUtil.readXMLFromFile(fileXMLInput);
    XMLUtil.signDocument (document,privateKey,certificate,"Person","data",DigestMethod.SHA1,SignatureMethod.RSA_SHA1);
    XMLUtil.saveXMLToFile(document, fileXMLSigned);

  }

}

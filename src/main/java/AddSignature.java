import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.security.KeyException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

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
    KeyStore.PrivateKeyEntry keyPair    = getKeyPair(keyStoreName, keyStorePassword, keyStoreType, keyAlias);
    PrivateKey               privateKey = keyPair.getPrivateKey();
    X509Certificate          certificate= (X509Certificate) keyPair.getCertificate();

    //SIGN DOCUMENT
    Document     document = readXMLFromFile(fileXMLInput);
    signDocument(document,privateKey,certificate,"Person","data",DigestMethod.SHA1,SignatureMethod.RSA_SHA1);
    saveXMLToFile(document, fileXMLSigned);

  }

  //================================================================================
  // READ XML FROM FILE
  //================================================================================
  // Document document = readXMLFromFile(fileXMLInput);
  private static Document readXMLFromFile(String fileName) throws Exception {
    DocumentBuilderFactory documentFactory = DocumentBuilderFactory.newInstance();
    documentFactory.setNamespaceAware(true);
    Document document = documentFactory.newDocumentBuilder().parse(new FileInputStream(fileName));
    return document;
  }

  //================================================================================
  // SAVE XML TO FILE
  //================================================================================
  private static void saveXMLToFile(Document document, String fileName) throws Exception {
    OutputStream       outputStream       = new FileOutputStream(fileName);
    TransformerFactory transformerFactory = TransformerFactory.newInstance();
    Transformer        transformer        = transformerFactory.newTransformer();
    transformer.transform(new DOMSource(document), new StreamResult(outputStream));
  }

  //================================================================================
  // SIGN DOCUMENT
  //================================================================================
  // <Person Id="data">
  public static void signDocument(
    Document        document,        //RETURN VALUE
    PrivateKey      privateKey,
    X509Certificate certificate,     //null or certificate for optional <KeyInfo>
    String          elementName,     //"Person"     FIX
    String          referenceURI,    //"data", ""
    String          digestMethod,    //DigestMethod.SHA1
    String          signatureMethod  //SignatureMethod.RSA_SHA1
  ) throws Exception {

    //CREATE SIGNATURE FACTORY
    XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");

    //GET KEY INFO
    KeyInfo keyInfo = null;
    if (certificate != null) { keyInfo = getKeyInfo(certificate, factory); }

    //GET REFERENCE
    Reference reference = factory.newReference(
      "#" + referenceURI,
      factory.newDigestMethod(digestMethod, null),
      Collections.singletonList(factory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)),
      null,
      null
    );

    //SPECIFY SIGNATURE TYPE
    SignedInfo signedInfo = factory.newSignedInfo(
      factory.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE,(C14NMethodParameterSpec) null),
      factory.newSignatureMethod(signatureMethod, null),Collections.singletonList(reference)
    );

    //SIGN DOCUMENT
    Element        element = (Element) document.getElementsByTagName(elementName).item(0);         //FIX
    DOMSignContext domSignContext = new DOMSignContext(privateKey, document.getDocumentElement());
                   domSignContext.setIdAttributeNS(element, null, "Id");                           //FIX
    XMLSignature   signature = factory.newXMLSignature(signedInfo, keyInfo);
                   signature.sign(domSignContext);

  }

  //================================================================================
  // GET KEY INFO
  //================================================================================
  private static KeyInfo getKeyInfo(
    X509Certificate     certificate,
    XMLSignatureFactory factory
  ) throws KeyException {

    //KEY INFO FACTORY
    KeyInfoFactory  keyInfoFactory     = factory.getKeyInfoFactory();

    //X509 DATA
    String          certificateName    = certificate.getSubjectX500Principal().getName();
    List            x509list           = new ArrayList();
                    x509list.add(certificateName);
                    x509list.add(certificate);
    X509Data        x509Data           = keyInfoFactory.newX509Data(x509list);

    //KEY VALUE
    KeyValue        keyValue           = keyInfoFactory.newKeyValue(certificate.getPublicKey());

    //CREATE KEY INFO
    List            items              = new ArrayList();
                    items.add(x509Data);
                    items.add(keyValue);
    KeyInfo         keyInfo            = keyInfoFactory.newKeyInfo(items);

    //RETURN KEY INFO
    return keyInfo;

  }

  //================================================================================
  // GET KEY PAIR
  //================================================================================
  private static KeyStore.PrivateKeyEntry getKeyPair(
    String keyStoreName,        //"src/main/resources/ClientKeyStore.jks"
    String keyStorePassword,    //"mypassword";
    String keyStoreType,        //"JKS"
    String keyAlias             //"clientkeys1"
  ) throws Exception {

    //GET PRIVATE KEY
    char[]                      password    = keyStorePassword.toCharArray();    //For KeyStore & Private Key
    KeyStore                    keyStore    = KeyStore.getInstance(keyStoreType);
                                keyStore.load(new FileInputStream(keyStoreName), password);
    KeyStore.PasswordProtection keyPassword = new KeyStore.PasswordProtection(   password);
    KeyStore.PrivateKeyEntry    keyPair = (KeyStore.PrivateKeyEntry) keyStore.getEntry(keyAlias,keyPassword);

    //RETURN KEY PAIR
    return keyPair;

  }

}

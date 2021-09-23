import org.w3c.dom.Document;
import org.w3c.dom.Element;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.Reference;
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
import java.security.Key;
import java.security.KeyException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class UtilSignature {

  //================================================================================
  // SIGN DOCUMENT
  //================================================================================
  // signDocument(document, Key, certificate, "Person", "#data", DigestMethod.SHA1, SignatureMethod.RSA_SHA1);
  // IF <Person Id="data"> THEN referenceURI="#data" AND FIX IS NEEDED
  // IF <Person>           THEN referenceURI=""      AND FIX IS NOT NEEDED
  public static void signDocument(
    Document        document,        //RETURN VALUE
    Key             key,             //Key used to sign XML Element
    X509Certificate certificate,     //null or certificate for optional <KeyInfo>
    String          elementName,     //"Person"     Element to Sign
    String          referenceURI,    //"#data", ""
    String          digestMethod,    //DigestMethod.SHA1
    String          signatureMethod  //SignatureMethod.RSA_SHA1
  ) throws Exception {

    //CREATE SIGNATURE FACTORY
    XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");

    //GET KEY INFO
    KeyInfo keyInfo = null;
    if (certificate != null) { keyInfo = constructKeyInfo(certificate, factory); }

    //GET REFERENCE
    Reference reference = factory.newReference(
      referenceURI,
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

    //PREPARE SIGN CONTEXT
    DOMSignContext domSignContext=new DOMSignContext(key, document.getElementsByTagName(elementName).item(0));

    //FIX IF referenceURI POINTS TO Id ATTRIBUTE
    if (!referenceURI.equals("") ) {
      Element element = (Element) document.getElementsByTagName(elementName).item(0);
      domSignContext.setIdAttributeNS(element, null, "Id");
    }

    //SIGN DOCUMENT
    XMLSignature   signature = factory.newXMLSignature(signedInfo, keyInfo);
                   signature.sign(domSignContext);

  }

  //================================================================================
  // CONSTRUCT KEY INFO
  //================================================================================
  private static KeyInfo constructKeyInfo(
    X509Certificate     certificate,
    XMLSignatureFactory factory
  ) throws KeyException {

    //KEY INFO FACTORY
    KeyInfoFactory keyInfoFactory     = factory.getKeyInfoFactory();

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
                    //items.add(keyValue);
    KeyInfo         keyInfo            = keyInfoFactory.newKeyInfo(items);

    //RETURN KEY INFO
    return keyInfo;

  }

}

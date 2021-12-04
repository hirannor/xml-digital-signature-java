package hu.eteosf.digitalsignature;

import org.w3c.dom.NodeList;

import javax.xml.crypto.OctetStreamData;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Result;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * An Implementation of {@link XmlDigitalSignature} API, which uses the javax.xml.crypto.dsig package
 * for generating and validating XML digital signatures.
 *
 * @author mate.karolyi
 */
public class XmlDigitalSignatureImpl implements XmlDigitalSignature {

    private static final String SIGNATURE_NODE = "Signature";

    // Ignoring line break characters at end of each line to avoid &#13; character
    // It can break the signature verification for external software like: Chilkat
    static {
        System.setProperty("com.sun.org.apache.xml.internal.security.ignoreLineBreaks", "true");
    }

    @Override
    public byte[] generateDetachedSignature(final Document document, final String digestMethod, final String signatureMethod) throws XmlDigitalSignatureException {
        try {
            final byte[] data = document.getData();
            final String fileName = document.getFileName();

            final KeyStore keyStore = KeyStoreUtil.loadKeyStore();
            final PrivateKey privateKey = KeyStoreUtil.getPrivateKey(keyStore);
            final X509Certificate certificate = KeyStoreUtil.getCertificate(keyStore);

            final XMLSignatureFactory signFactory = XMLSignatureFactory.getInstance("DOM");
            final Reference ref = signFactory.newReference(
                    fileName, signFactory.newDigestMethod(digestMethod, null)
            );

            final SignedInfo signedInfo = signFactory.newSignedInfo(
                    signFactory
                            .newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null),
                    signFactory.newSignatureMethod(signatureMethod, null),
                    Collections.singletonList(ref)
            );

            final KeyInfoFactory keyInfoFactory = signFactory.getKeyInfoFactory();
            final List<Object> x509Content = new ArrayList<>();
            x509Content.add(certificate.getSubjectX500Principal().getName());
            x509Content.add(certificate);
            keyInfoFactory.newX509Data(x509Content);

            final KeyValue keyValue = keyInfoFactory.newKeyValue(certificate.getPublicKey());
            final KeyInfo keyInfo = keyInfoFactory.newKeyInfo(Collections.singletonList(keyValue));
            final XMLSignature signature = signFactory.newXMLSignature(signedInfo, keyInfo);

            final DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
            docBuilderFactory.setNamespaceAware(true);

            final org.w3c.dom.Document signatureDoc = docBuilderFactory.newDocumentBuilder().newDocument();
            final DOMSignContext signContext = new DOMSignContext(privateKey, signatureDoc);

            signContext.setURIDereferencer((uriReference, context) ->
                    new OctetStreamData(new ByteArrayInputStream(data))
            );
            signature.sign(signContext);

            return transformDocument(signatureDoc);
        } catch (Exception ex) {
            throw new XmlDigitalSignatureException("Error occurred on signing document: ", ex);
        }
    }

    @Override
    public boolean verifyDetachedSignature(byte[] document, byte[] signedDocument) throws XmlDigitalSignatureException {
        try {
            final KeyStore keyStore = KeyStoreUtil.loadKeyStore();

            final X509Certificate certificate = KeyStoreUtil.getCertificate(keyStore);
            final PublicKey publicKey = certificate.getPublicKey();

            final DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
            documentBuilderFactory.setNamespaceAware(true);

            final DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
            final org.w3c.dom.Document signatureDocument = documentBuilder.parse(new ByteArrayInputStream(signedDocument));

            final NodeList nodeList = signatureDocument.getElementsByTagNameNS(XMLSignature.XMLNS, SIGNATURE_NODE);
            NodeList signatureNode = signatureDocument.getElementsByTagNameNS(XMLSignature.XMLNS, SIGNATURE_NODE);

            if (nodeList == null || nodeList.getLength() == 0) {
                signatureNode = signatureDocument.getDocumentElement().getElementsByTagName(SIGNATURE_NODE);
            }
            final boolean isSigAvailable = Optional.ofNullable(signatureNode).map(it -> it.getLength() != 0).isPresent();

            if (!isSigAvailable) {
                throw new XmlDigitalSignatureException("Signature node not present!");
            }

            final XMLValidateContext valContext = new DOMValidateContext(publicKey, signatureNode.item(0));

            valContext.setURIDereferencer((uriReference, context) ->
                    new OctetStreamData(new ByteArrayInputStream(document))
            );

            final XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance("DOM");
            final XMLSignature signature = signatureFactory.unmarshalXMLSignature(valContext);

            return signature.validate(valContext);
        } catch (Exception ex) {
            throw new XmlDigitalSignatureException("Error occurred on verifying document: ", ex);
        }
    }

    private byte[] transformDocument(final org.w3c.dom.Document document) throws TransformerException {
        final Transformer transformer = TransformerFactory.newInstance().newTransformer();

        final StringWriter writer = new StringWriter();
        final Result result = new StreamResult(writer);
        final DOMSource source = new DOMSource(document);
        transformer.transform(source, result);

        return writer.getBuffer().toString()
                .getBytes(StandardCharsets.UTF_8);
    }
}

package hu.eteosf.digitalsignature;

/**
 * XML Digital Signature API for generating and validating digital signatures.
 *
 * @author mate.karolyi
 */
public interface XmlDigitalSignature {

     /**
      * Creates a detached signature for the given document.
      * A detached signature is a type of digital signature that is kept separate from its signed data,
      * as opposed to bundled together into a single file.
      *
      * @param document {@link Document} to be signed
      * @param digestMethod used digest method, see {@link javax.xml.crypto.dsig.DigestMethod}
      * @param signatureMethod used signature method, see {@link javax.xml.crypto.dsig.SignatureMethod}
      * @return the byte array of the detached signature
      * @throws {@link XmlDigitalSignatureException} in case of any error during the sign process
      */
     byte[] generateDetachedSignature(final Document document, final String digestMethod, final String signatureMethod) throws XmlDigitalSignatureException;

     /**
      * Verifies the detached signature for the given document.
      *
      * @param document original document,
      * @param signedDocument the digitally signed document
      * @return the result of the verification
      * @throws {@link XmlDigitalSignatureException} in case of any error during the verification process
      */
     boolean verifyDetachedSignature(byte[] document, byte[] signedDocument) throws XmlDigitalSignatureException;
}


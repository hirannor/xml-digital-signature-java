package hu.eteosf.digitalsignature;

import org.junit.Assert;
import org.junit.Test;

import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.SignatureMethod;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;

public class XmlDigitalSignatureTest {

    private static final String DOCUMENT = "document.xml";
    private static final String SIGNATURE_DOCUMENT = "document.sign.xml";

    final XmlDigitalSignature xmlDigitalSignature = new XmlDigitalSignatureImpl();

    @Test
    public void testSignAndVerifySignature() throws Exception {
        // given
        byte[] data = loadFileFromClassPath(DOCUMENT);
        final Document document = new Document(DOCUMENT, data);

        // when
        byte[] signedDocument = xmlDigitalSignature.generateDetachedSignature(document, DigestMethod.SHA512, SignatureMethod.RSA_SHA512);

        boolean verified = xmlDigitalSignature.verifyDetachedSignature(data, signedDocument);

        // then
        Assert.assertTrue("Verification of signature should be true", verified);
    }

    @Test
    public void testVerifySignature() throws Exception {
        // given
        byte[] data = loadFileFromClassPath(DOCUMENT);
        byte[] signature = loadFileFromClassPath(SIGNATURE_DOCUMENT);

        // when
        boolean verified = xmlDigitalSignature.verifyDetachedSignature(data, signature);

        // then
        Assert.assertTrue("Verification of signature should be true", verified);
    }

    private byte[] loadFileFromClassPath(final String path) throws IOException {
        final InputStream inputStream = getClass().getClassLoader().getResourceAsStream(path);

        if (inputStream == null) {
            throw new FileNotFoundException("Resource not found: " + path);
        }
        return inputStream.readAllBytes();
    }
}

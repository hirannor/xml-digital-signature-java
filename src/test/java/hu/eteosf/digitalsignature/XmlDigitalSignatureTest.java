package hu.eteosf.digitalsignature;

import org.junit.Assert;
import org.junit.Test;

import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.SignatureMethod;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;

public class XmlDigitalSignatureTest {

    private static final String FILE_NAME = "document.xml";

    final XmlDigitalSignature xmlDigitalSignature = new XmlDigitalSignatureImpl();

    @Test
    public void testSignAndVerifySignature() throws Exception {
        // given
        byte[] data = loadFileFromClassPath(FILE_NAME);
        final Document document = new Document(FILE_NAME, data);

        // when
        byte[] signedDocument = xmlDigitalSignature.generateDetachedSignature(document, DigestMethod.SHA512, SignatureMethod.RSA_SHA512);
        boolean verified = xmlDigitalSignature.verifyDetachedSignature(data, signedDocument);

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

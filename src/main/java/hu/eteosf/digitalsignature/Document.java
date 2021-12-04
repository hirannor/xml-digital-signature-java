package hu.eteosf.digitalsignature;

/**
 * Describes the document to be signed.
 *
 * @author mate.karolyi
 */
public class Document {
    private String fileName;
    private byte[] data;

    public Document(String fileName, byte[] data) {
        this.fileName = fileName;
        this.data = data;
    }

    public String getFileName() {
        return fileName;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    public byte[] getData() {
        return data;
    }

    public void setData(byte[] data) {
        this.data = data;
    }
}

package hu.signatures.samples.itextlibrary.util;

import com.itextpdf.text.pdf.*;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
public class PdfAttachmentExtractor {

    public byte[] getXmlAttachment(byte[] pdfIn) throws IOException {

        PdfReader reader = new PdfReader(pdfIn);
        PdfDictionary root = reader.getCatalog();
        PdfDictionary documentNames = root.getAsDict(PdfName.NAMES);
        if (documentNames == null) {
            reader.close();
            return new byte[0];
        }
        PdfDictionary embeddedFiles = documentNames.getAsDict(PdfName.EMBEDDEDFILES);
        PdfArray fileSpecificationArray = embeddedFiles.getAsArray(PdfName.NAMES);
        for (int i = 1; i < fileSpecificationArray.size(); i += 2) {
            PdfDictionary fileSpecification = fileSpecificationArray.getAsDict(i);
            PdfDictionary refs = fileSpecification.getAsDict(PdfName.EF);
            for (PdfName key : refs.getKeys()) {
                String fileName = fileSpecification.getAsString(key).toString();
                if (!fileName.endsWith(".xml")) {
                    continue;
                }
                PRStream stream = (PRStream) PdfReader.getPdfObject(refs.getAsIndirectObject(key));
                return PdfReader.getStreamBytes(stream);
            }
        }
        reader.close();
        return new byte[0];
    }
}

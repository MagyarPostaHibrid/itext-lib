package hu.signatures.samples.itextlibrary.pdfgenerator;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class EmbeddedDocumentDTO {

    private String documentName;

    private byte[] documentData;
}

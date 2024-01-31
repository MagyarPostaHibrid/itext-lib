package hu.signatures.samples.itextlibrary.pdfgenerator;

import com.itextpdf.text.Document;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.FontProvider;
import com.itextpdf.text.pdf.PdfWriter;
import com.itextpdf.tool.xml.Pipeline;
import com.itextpdf.tool.xml.XMLWorker;
import com.itextpdf.tool.xml.XMLWorkerHelper;
import com.itextpdf.tool.xml.css.CssFilesImpl;
import com.itextpdf.tool.xml.css.StyleAttrCSSResolver;
import com.itextpdf.tool.xml.html.CssAppliersImpl;
import com.itextpdf.tool.xml.html.Tags;
import com.itextpdf.tool.xml.parser.XMLParser;
import com.itextpdf.tool.xml.pipeline.css.CssResolverPipeline;
import com.itextpdf.tool.xml.pipeline.end.PdfWriterPipeline;
import com.itextpdf.tool.xml.pipeline.html.HtmlPipeline;
import com.itextpdf.tool.xml.pipeline.html.HtmlPipelineContext;
import com.itextpdf.tool.xml.pipeline.html.ImageProvider;
import hu.signatures.samples.itextlibrary.exception.ITextLibraryException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static com.itextpdf.text.pdf.PdfWriter.VERSION_1_7;

@Slf4j
@Service
public class PdfGeneratorEngine {

    private final FontProvider fontProvider;
    private final ImageProvider imageProvider;

    public PdfGeneratorEngine() {
        this.fontProvider = new CustomFontProvider("fonts/AndBasR.ttf");
        this.imageProvider = new CustomImageProvider();
    }

    /**
     * Generates a stylized pdf for the given attachment instance.
     * Notes:
     * - attachment should be serialized without embedded documents
     *
     * @param embeddedDocuments  documents stored in the attachment
     * @param htmlData
     * @param attachment         a serialized instance of the attachment without the embedded documents
     * @param cssData
     * @param attachmentFileName <p>
     */
    public byte[] generatePdf(
            List<EmbeddedDocumentDTO> embeddedDocuments,
            byte[] htmlData,
            byte[] attachment,
            String attachmentFileName,
            byte[] cssData
    ) {
        try (
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                InputStream htmlIs = new ByteArrayInputStream(htmlData);
                InputStream cssIs = new ByteArrayInputStream(cssData);
        ) {
            Document document = new Document();
            PdfWriter writer = PdfWriter.getInstance(document, baos);
            writer.setAtLeastPdfVersion(VERSION_1_7);
            document.setMargins(0, 0, 0, 0);
            document.open();

            parseXHtml(writer, document, htmlIs, cssIs, StandardCharsets.UTF_8, fontProvider);

            writer.addFileAttachment(attachmentFileName, attachment, null, attachmentFileName);

            if (embeddedDocuments != null) {
                for (EmbeddedDocumentDTO embeddedDocument : embeddedDocuments) {
                    String documentName = embeddedDocument.getDocumentName();
                    if (documentName == null || documentName.isEmpty()) {
                        throw new IllegalArgumentException("EmbeddedDocument.documentName can't be null or empty");
                    }
                    byte[] documentData = embeddedDocument.getDocumentData();
                    if (documentData == null) {
                        throw new IllegalArgumentException("EmbeddedDocument.documentData can't be null");
                    }
                    writer.addFileAttachment(documentName, documentData, null, documentName);
                }
            }
            document.close();
            return baos.toByteArray();
        } catch (DocumentException | IOException | RuntimeException e) {
            String xml = new String(attachment);
            log.error("Error generating PDF; attachment is:\n{}", xml);
            throw new ITextLibraryException("Error generating PDF: " + e.getMessage(), e);
        }
    }

    private void parseXHtml(
            PdfWriter writer,
            Document document,
            InputStream htmlIn,
            InputStream cssIn,
            Charset charset,
            FontProvider fontProvider
    ) throws IOException {
        CssFilesImpl cssFiles = new CssFilesImpl();
        cssFiles.add(XMLWorkerHelper.getCSS(cssIn));
        StyleAttrCSSResolver cssResolver = new StyleAttrCSSResolver(cssFiles);
        HtmlPipelineContext htmlPipelineContext = new HtmlPipelineContext(new CssAppliersImpl(fontProvider));
        htmlPipelineContext.setImageProvider(imageProvider);
        htmlPipelineContext.setAcceptUnknown(true).autoBookmark(true).setTagFactory(Tags.getHtmlTagProcessorFactory());
        HtmlPipeline htmlPipeline = new HtmlPipeline(htmlPipelineContext, new PdfWriterPipeline(document, writer));
        Pipeline<?> pipeline = new CssResolverPipeline(cssResolver, htmlPipeline);
        XMLWorker worker = new XMLWorker(pipeline, true);
        XMLParser xmlParser = new XMLParser(true, worker, charset);
        if (charset != null) {
            xmlParser.parse(htmlIn, charset);
        } else {
            xmlParser.parse(htmlIn);
        }
    }

}


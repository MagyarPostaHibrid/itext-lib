package hu.signatures.samples.itextlibrary.pdfgenerator;

import com.itextpdf.text.BaseColor;
import com.itextpdf.text.Font;
import com.itextpdf.text.pdf.BaseFont;
import com.itextpdf.tool.xml.XMLWorkerFontProvider;
import hu.signatures.samples.itextlibrary.exception.ITextLibraryException;

public class CustomFontProvider extends XMLWorkerFontProvider {

    private final BaseFont baseFont;

    public CustomFontProvider(String fontFilePath) {
        try {
            baseFont = BaseFont.createFont(fontFilePath, BaseFont.IDENTITY_H, true);
        } catch (Exception e) {
            throw new ITextLibraryException(e);
        }
    }

    @Override
    public boolean isRegistered(String fontName) {
        try {
            Font fontToCheck = getFont(fontName);
            if (fontToCheck.getFamily() == Font.FontFamily.UNDEFINED) {
                return false;
            }
        } catch (Exception e) {
            return false;
        }
        return true;
    }

    @Override
    public Font getFont(String fontName, String encoding, boolean embedded, float size, int style, BaseColor color) {
        if (fontName == null) {
            return super.getFont(null, encoding, embedded, size, style, color);
        }
        return new Font(baseFont, size, style, color);
    }
}

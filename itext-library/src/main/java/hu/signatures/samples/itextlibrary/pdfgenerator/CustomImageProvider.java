package hu.signatures.samples.itextlibrary.pdfgenerator;

import com.itextpdf.text.Image;
import com.itextpdf.tool.xml.exceptions.NotImplementedException;
import com.itextpdf.tool.xml.pipeline.html.AbstractImageProvider;
import hu.signatures.samples.itextlibrary.exception.ITextLibraryException;

import java.net.URL;
import java.util.HashMap;
import java.util.Map;

public class CustomImageProvider extends AbstractImageProvider {

    private final Map<String, Image> imagesMap = new HashMap<>();

    @Override
    public String getImageRootPath() {
        throw new NotImplementedException();
    }

    @Override
    public Image retrieve(String src) {
        String resourcePath = src.replace("/src/main/resources/", "");
        Image image = imagesMap.get(resourcePath);
        if (image != null) {
            return image;
        }
        URL url = CustomImageProvider.class.getClassLoader().getResource(resourcePath);
        if (url == null)
            throw new ITextLibraryException("Resource not found: " + resourcePath);
        try {
            image = Image.getInstance(url);
            imagesMap.put(resourcePath, image);
            return image;
        } catch (Exception e) {
            throw new ITextLibraryException("Error loading image " + url, e);
        }
    }
}

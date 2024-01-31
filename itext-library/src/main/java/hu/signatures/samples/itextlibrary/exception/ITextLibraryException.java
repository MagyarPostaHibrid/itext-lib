package hu.signatures.samples.itextlibrary.exception;

public class ITextLibraryException extends RuntimeException {

    public ITextLibraryException(String message) {
        super(message);
    }

    public ITextLibraryException(Throwable throwable) {
        super(throwable);
    }

    public ITextLibraryException(String message, Throwable throwable) {
        super(message, throwable);
    }
}

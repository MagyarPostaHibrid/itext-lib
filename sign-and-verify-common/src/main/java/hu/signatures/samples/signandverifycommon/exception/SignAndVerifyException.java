package hu.signatures.samples.signandverifycommon.exception;

public class SignAndVerifyException extends RuntimeException {

    public SignAndVerifyException(String message) {
        super(message);
    }

    public SignAndVerifyException(Throwable throwable) {
        super(throwable);
    }

    public SignAndVerifyException(String message, Throwable throwable) {
        super(message, throwable);
    }
}

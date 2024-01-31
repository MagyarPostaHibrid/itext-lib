package hu.signatures.samples.signandverifycommon.dto;

import lombok.Getter;
import lombok.Setter;
import lombok.SneakyThrows;
import org.bouncycastle.cms.SignerId;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

@Getter
@Setter
public class SignatureInfoDTO {

    private String signatureName;

    private boolean signatureCoversWholeDocument;

    private int signedRevision;

    private int lastRevision;

    private boolean signLastRevision;

    private Date signatureDate;

    private X509Certificate certificate;

    private String certificateFingerprintSha1;

    private boolean timestamped;

    private boolean timestampVerified;

    private boolean timestampCertificateRecognized;

    private SignerId timestampSignerId;

    private Date timestampDate;

    private boolean signatureVerified;

    private SignatureType signatureType;

    private X509Certificate issuerCertificate;

    private String issuerCertificateFingerprintSha1;

    private boolean certificateRecognized;

    private boolean certificateTrusted;

    private boolean certificateExpired;

    private boolean certificateRevoked;

    private RevocationSource revocationSource;

    private boolean ocspValidationPerformed;

    private boolean crlOfflineValidationPerformed;

    private boolean crlOnlineValidationPerformed;

    private boolean certificateQualified = true;

    private List<String> asiceContainerContents;

    private boolean isTsp = false;

    public SignatureInfoDTO() {
        this.signatureType = SignatureType.UNKNOWN;
    }

    public SignatureInfoDTO(SignatureType signatureType) {
        this.signatureType = signatureType;
    }

    public boolean isCertificateValidWhenSigning() {
        Date signingDate = isTimestamped() ? getTimestampDate() : getSignatureDate();
        if (signingDate == null || signingDate.after(getCertificate().getNotAfter())) {
            return false;
        }
        return !signingDate.before(getCertificate().getNotBefore());
    }

    public boolean isTimestampOk() {
        return timestamped && timestampVerified && timestampCertificateRecognized;
    }

    @Override
    public String toString() {
        return "SignatureInfo [signatureName=" + signatureName + ", signatureCoversWholeDocument="
                + signatureCoversWholeDocument + ", certificateFingerprintSha1=" + certificateFingerprintSha1
                + ", timestampCertificateRecognized=" + timestampCertificateRecognized + ", signatureVerified="
                + signatureVerified + "]";
    }

    @SneakyThrows
    public String getDescription() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(out, false, StandardCharsets.UTF_8);
        print(ps);
        ps.flush();
        return new String(out.toByteArray(), StandardCharsets.UTF_8);
    }

    public void print(PrintStream out) {
        out.println("Signature name: " + this.signatureName);
        out.println("Signature date: " + this.signatureDate);
        out.println("Signed revision: " + this.signedRevision);
        out.println("Sign last revision: " + this.signLastRevision);
        out.println("signature covers whole document: " + this.signatureCoversWholeDocument);
        out.println("Signature verified: " + this.signatureVerified);
        if (this.timestamped) {
            out.println("Signature timestamped: true");
            out.println("Timestamp date: " + this.timestampDate);
            out.println("Timestamp verified: " + this.timestampVerified);
            out.println("Timestamp certificate Recognized: " + this.timestampCertificateRecognized);
        } else {
            out.println("Signature timestamped: false");
        }
        out.println("Certificate subjectDN: " + this.certificate.getSubjectDN());
        out.println("Certificate issuerDN: " + this.certificate.getIssuerDN());
        out.println("Certificate FingerPrint (SHA-1): " + this.certificateFingerprintSha1);
        out.println("Certificate Recognized: " + this.certificateRecognized);
        out.println("Certificate Trusted: " + certificateTrusted);
        out.println("Certificate Expired: " + this.certificateExpired);
        if (this.certificateRevoked) {
            out.println("Certificate Revoked: true (" + this.revocationSource + ")");
        } else {
            out.println("Certificate Revoked: false");
        }
        out.println("Certificate valid when signing: " + this.isCertificateValidWhenSigning());
    }
}

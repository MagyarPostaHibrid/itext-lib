package hu.signatures.samples.itextlibrary.verify;

import static hu.signatures.samples.signandverifycommon.util.KeystoreUtils.loadKeystore;
import static java.util.function.Predicate.not;

import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.security.CRLVerifier;
import com.itextpdf.text.pdf.security.CertificateVerification;
import com.itextpdf.text.pdf.security.EncryptionAlgorithms;
import com.itextpdf.text.pdf.security.OCSPVerifier;
import com.itextpdf.text.pdf.security.PdfPKCS7;
import hu.signatures.samples.signandverifycommon.configuration.AlgorithmsConfiguration;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TimeStampToken;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TimeStampToken;
import org.springframework.stereotype.Service;

import hu.signatures.samples.itextlibrary.exception.ITextLibraryException;
import hu.signatures.samples.signandverifycommon.configuration.OnlineVerificationConfiguration;
import hu.signatures.samples.signandverifycommon.configuration.TruststoreConfiguration;
import hu.signatures.samples.signandverifycommon.dto.RevocationSource;
import hu.signatures.samples.signandverifycommon.dto.SignatureInfoDTO;
import hu.signatures.samples.signandverifycommon.dto.SignatureType;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class PdfSignatureVerifierService {

    private final KeyStore trustStore;
    private final List<X509CRL> crlList;
    private final OnlineVerificationConfiguration onlineVerificationConfiguration;
    private final AlgorithmsConfiguration algorithmsConfiguration;

    public PdfSignatureVerifierService(TruststoreConfiguration truststoreConfiguration, OnlineVerificationConfiguration onlineVerificationConfiguration, AlgorithmsConfiguration algorithmsConfiguration) {
        this.onlineVerificationConfiguration = onlineVerificationConfiguration;
        this.algorithmsConfiguration = algorithmsConfiguration;
        trustStore = loadKeystore(truststoreConfiguration.getLocation(), truststoreConfiguration.getType(), truststoreConfiguration.getPassword());
        crlList = readCRLsFromFolder(onlineVerificationConfiguration.getCrlListLocation());
        Security.addProvider(new BouncyCastleProvider());
        addAlgorithmsToItext5();
    }

    /**
     * This method is called in the constructor and is used to avoid the following exception when verifying documents.
     * java.security.NoSuchAlgorithmException: SHA256with1.2.840.10045.4.3.2 Signature not available
     * This exception is caused by an unsupported ECDSA SHA256 signature in iText5.
     * See <a href="https://stackoverflow.com/questions/46346144/digital-signature-verification-with-itext-not-working">...</a>
     */
    private void addAlgorithmsToItext5() {
        log.info("Putting algorithms to the map of encryption algorithms in itext");
        try {
            for (AlgorithmsConfiguration.Algorithm algorithm : algorithmsConfiguration.getAlgorithms()) {
                EncryptionAlgorithms.addAlgorithm(algorithm.getOid(), algorithm.getName());
            }
        } catch (Exception e) {
            log.warn("Adding algorithm to PDF Signature Verifier Service has failed. This can cause problems later on when verifying documents!");
            log.warn(e.getMessage(), e);
        }
    }

    private List<X509CRL> readCRLsFromFolder(String path) {
        List<X509CRL> returnList = new ArrayList<>(List.of());
        if (path == null || path.isEmpty()) {
            log.debug("No local CRL configured");
            return returnList;
        }
        CertificateFactory certificateFactory;
        try {
            certificateFactory = CertificateFactory.getInstance("X509");
        } catch (CertificateException e) {
            throw new ITextLibraryException(e);
        }

        File folder = new File(path);
        if (!folder.isDirectory()) {
            return returnList;
        }
        List<File> files = Arrays.stream(Objects.requireNonNull(folder.listFiles())).filter(file -> file.getName().toLowerCase().endsWith(".crl")).collect(Collectors.toList());

        for (var file : files) {
            try {
                returnList.add((X509CRL) certificateFactory.generateCRL(new FileInputStream(file)));
            } catch (CRLException | FileNotFoundException e) {
                throw new ITextLibraryException(e);
            }
        }

        return returnList;
    }

    public List<SignatureInfoDTO> verifySignatures(byte[] pdfIn) {
        log.debug("verifySignatures() called");
        PdfReader reader;
        try {
            reader = new PdfReader(new ByteArrayInputStream(pdfIn));
        } catch (IOException e) {
            throw new ITextLibraryException(e);
        }
        List<SignatureInfoDTO> signatureInfos = new ArrayList<>();
        try {
            AcroFields acroFields = reader.getAcroFields();
            int lastRevision = acroFields.getTotalRevisions();
            log.debug("lastRevision: " + lastRevision);

            for (String signatureName : acroFields.getSignatureNames()) {
                signatureInfos.add(getSignatureInfo(acroFields, signatureName));
            }

        } catch (RuntimeException | GeneralSecurityException e) {
            log.error(e.getMessage(), e);
            throw new ITextLibraryException("Error verifying signature", e);
        }
        return signatureInfos.stream()
                .filter(not(SignatureInfoDTO::isTsp))
                .collect(Collectors.toList());
    }

    private SignatureInfoDTO getSignatureInfo(AcroFields acroFields, String signatureName) throws GeneralSecurityException {
        log.debug("Signatures name: " + signatureName);

        SignatureInfoDTO signatureInfoDTO = new SignatureInfoDTO(SignatureType.PADES);
        signatureInfoDTO.setSignatureName(signatureName);
        int revision = acroFields.getRevision(signatureName);
        signatureInfoDTO.setSignedRevision(revision);
        signatureInfoDTO.setLastRevision(acroFields.getTotalRevisions());
        signatureInfoDTO.setSignLastRevision(revision == acroFields.getTotalRevisions());
        signatureInfoDTO.setSignatureCoversWholeDocument(acroFields.signatureCoversWholeDocument(signatureName));

        PdfPKCS7 signature = acroFields.verifySignature(signatureName);
        signatureInfoDTO.setSignatureVerified(signature.verify());
        Calendar signDate = signature.getSignDate();

        X509Certificate signingCertificate = signature.getSigningCertificate();
        signatureInfoDTO.setCertificate(signingCertificate);
        signatureInfoDTO.setCertificateFingerprintSha1(generateFingerprintSha1(signingCertificate));

        signatureInfoDTO.setTsp(signature.isTsp());

        signatureInfoDTO.setSignatureDate(signDate == null ? null : signDate.getTime());
        verifySignatureTimestamp(signature, signatureInfoDTO);

        verifyCertificates(signatureInfoDTO, signature.getSignCertificateChain(), signature.getSignDate(), signature.getCRLs());
        X509Certificate issuerCert = (X509Certificate) trustStore.getCertificate(signingCertificate.getIssuerX500Principal().getName());
        checkOnline(signatureInfoDTO, signingCertificate, issuerCert, signDate.getTime());

        if (log.isDebugEnabled()) {
            logSignatureInfo(signatureInfoDTO);
        }

        log.debug("\n***Sign. info ***\n{}\n\n", signatureInfoDTO);
        return signatureInfoDTO;
    }

    private void verifySignatureTimestamp(PdfPKCS7 signature, SignatureInfoDTO signatureInfoDTO) throws GeneralSecurityException {
        TimeStampToken timestamp = signature.getTimeStampToken();
        if (timestamp != null) {
            signatureInfoDTO.setTimestamped(true);
            signatureInfoDTO.setTimestampSignerId(timestamp.getSID());
            Calendar timeStampDate = signature.getTimeStampDate();
            signatureInfoDTO.setTimestampDate(timeStampDate.getTime());
            if (signatureInfoDTO.getSignatureDate() == null) {
                signatureInfoDTO.setSignatureDate(timeStampDate.getTime());
            }
            if (signature.verifyTimestampImprint()) {
                signatureInfoDTO.setTimestampVerified(true);
                signatureInfoDTO.setTimestampCertificateRecognized(CertificateVerification.verifyTimestampCertificates(timestamp, trustStore, null));
            }
        }
    }

    private void verifyCertificates(SignatureInfoDTO signatureInfoDTO, Certificate[] certificateChain, Calendar signDate, Collection<? extends CRL> crlsFromSignature) {

        Collection<CRL> mergedCrls = mergeCRL(crlList, crlsFromSignature);
        var verificationExceptions = CertificateVerification.verifyCertificates(certificateChain, trustStore, mergedCrls, signDate);
        signatureInfoDTO.setCertificateRecognized(verificationExceptions.isEmpty());
        for (var verificationResponse : verificationExceptions) {
            log.debug(verificationResponse.getMessage());
        }
        checkOfflineCRLs(signatureInfoDTO, (X509Certificate) certificateChain[0], crlList);
    }

    private Collection<CRL> mergeCRL(Collection<? extends CRL> crl1, Collection<? extends CRL> crl2) {
        Set<CRL> result = new HashSet<>();
        if (crl1 != null) result.addAll(crl1);
        if (crl2 != null) result.addAll(crl2);
        return result;
    }

    private void checkOfflineCRLs(SignatureInfoDTO signatureInfoDTO, X509Certificate certificate, Collection<? extends CRL> crls) {
        if (crls == null || crls.isEmpty()) {
            log.debug("No local CRLs used");
            return;
        }
        signatureInfoDTO.setCrlOfflineValidationPerformed(true);

        for (CRL crl : crls) {
            X509CRL x509crl = (X509CRL) crl;
            log.trace(String.format("Checking local CRL %s [%s -> %s]", x509crl.getIssuerDN().getName(), x509crl.getThisUpdate(), x509crl.getNextUpdate()));
            if (crl.isRevoked(certificate)) {
                log.info(String.format("### Certificate revoked from CRL:%n Certificate=%s;%n CRL=%s;", certificate.getSubjectDN().getName(), x509crl.getIssuerDN().getName()));
                signatureInfoDTO.setCertificateRevoked(true);
                signatureInfoDTO.setRevocationSource(RevocationSource.CRL_OFFLINE);
                return;
            }
        }
        log.debug("Certificate not present in local CRLs");
    }

    private void checkOnline(SignatureInfoDTO signatureInfoDTO, X509Certificate signCert, X509Certificate issuerCert, Date signDate) {
        if (!signatureInfoDTO.isCertificateRevoked()) {
            checkOnlineOCSP(signatureInfoDTO, signCert, issuerCert, signDate);
        }
        if (!signatureInfoDTO.isCertificateRevoked()) {
            checkOnlineCRL(signatureInfoDTO, signCert, issuerCert, signDate);
        }
    }

    private void checkOnlineOCSP(SignatureInfoDTO signatureInfoDTO, X509Certificate signCert, X509Certificate issuerCert, Date signDate) {
        if (onlineVerificationConfiguration.isOcspValidationDisabled()) {
            log.info("OCSP validation is disabled");
            return;
        }
        try {
            var ocspVerifier = new OCSPVerifier(null, null);
            boolean result = !ocspVerifier.verify(signCert, issuerCert, signDate).isEmpty();
            if (result) {
                signatureInfoDTO.setOcspValidationPerformed(true);
                log.info(String.format("Certificate verified by OCSP: %s", signCert.getSubjectDN().getName()));
            }
        } catch (CertificateException e) {
            signatureInfoDTO.setOcspValidationPerformed(true);
            log.info(String.format("Certificate revoked by OCSP %s: %s", signCert.getSubjectDN().getName(), e.getMessage()));
            signatureInfoDTO.setCertificateRevoked(true);
        } catch (GeneralSecurityException | IOException e) {
            signatureInfoDTO.setOcspValidationPerformed(true);
            log.warn("Error during online certificate validation: " + e.getMessage(), e);
        }
    }

    private void checkOnlineCRL(SignatureInfoDTO signatureInfoDTO, X509Certificate signCert, X509Certificate issuerCert, Date signDate) {
        if (onlineVerificationConfiguration.isCrlOnlineValidationDisabled()) {
            log.info("CRL ONLINE validation is disabled");
            return;
        }
        try {
            var crlVerifier = new CRLVerifier(null, crlList);
            boolean result = !crlVerifier.verify(signCert, issuerCert, signDate).isEmpty();
            if (result) {
                signatureInfoDTO.setCrlOnlineValidationPerformed(true);
                log.info("Certificate verified by Online CRL: " + signCert.getSubjectDN().getName());
            }
        } catch (CertificateException e) {
            signatureInfoDTO.setCrlOnlineValidationPerformed(true);
            signatureInfoDTO.setCertificateRevoked(true);
            log.info(String.format("Online CRL validation failed for certificate %s: %s", signCert.getSubjectDN().getName(), e.getMessage()));
        } catch (GeneralSecurityException | IOException e) {
            signatureInfoDTO.setCrlOnlineValidationPerformed(true);
            log.warn("Error during online certificate validation: " + e.getMessage(), e);
        }
    }

    private void logSignatureInfo(SignatureInfoDTO signatureInfoDTO) {
        if (signatureInfoDTO.isSignatureVerified() && !signatureInfoDTO.isCertificateRevoked() && !signatureInfoDTO.isCertificateExpired() && signatureInfoDTO.isCertificateRecognized()) {
            log.debug("Signature verified: " + signatureInfoDTO.isSignatureVerified());
            log.debug("Signature revoked: " + signatureInfoDTO.isCertificateRevoked());
            log.debug("Signature expired: " + signatureInfoDTO.isCertificateExpired());
            log.debug("Signature coversWholeDoc: " + signatureInfoDTO.isSignatureCoversWholeDocument());
            log.debug("Signature recognized: " + signatureInfoDTO.isCertificateRecognized());
            log.debug("Signature last revision: " + signatureInfoDTO.isSignLastRevision());
        }
    }

    /**
     * Generates the SHA-1 fingerprint for a given X.509 certificate.
     *
     * @param certificate The X.509 certificate for which to compute the SHA-1 fingerprint.
     * @return A hexadecimal representation of the SHA-1 fingerprint, separated by the specified separator.
     * @throws ITextLibraryException if there is an issue encoding the certificate or if the SHA-1 algorithm is not supported.
     */
    private String generateFingerprintSha1(Certificate certificate) {
        try {
            byte[] hash = generateHash(certificate.getEncoded(), "SHA-1");
            return bytesToHex(hash, ":");
        } catch (CertificateEncodingException | NoSuchAlgorithmException e) {
            throw new ITextLibraryException(e);
        }
    }

    /**
     * Generates a hash of the given data using the specified hashing algorithm.
     *
     * @param data      The data to be hashed.
     * @param algorithm The name of the hashing algorithm to use (e.g., "SHA-1", "SHA-256").
     * @return The computed hash as an array of bytes.
     * @throws NoSuchAlgorithmException if the specified hashing algorithm is not available.
     */
    public byte[] generateHash(byte[] data, String algorithm) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(algorithm);
        digest.update(data);
        return digest.digest();
    }

    /**
     * Converts an array of bytes to a hexadecimal string with an optional separator.
     *
     * @param bytes     The array of bytes to convert to hexadecimal representation.
     * @param separator The separator to insert between each pair of hexadecimal digits (e.g., ":" or "" for no separator).
     * @return The hexadecimal representation of the input bytes as a string.
     */
    private String bytesToHex(byte[] bytes, String separator) {
        StringBuilder stringBuffer = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            if (i != 0) {
                stringBuffer.append(separator);
            }
            stringBuffer.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
        }
        return stringBuffer.toString().toUpperCase();
    }
}

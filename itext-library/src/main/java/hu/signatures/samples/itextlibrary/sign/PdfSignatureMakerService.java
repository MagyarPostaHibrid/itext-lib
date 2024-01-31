package hu.signatures.samples.itextlibrary.sign;

import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.*;
import hu.signatures.samples.itextlibrary.exception.ITextLibraryException;
import hu.signatures.samples.itextlibrary.exception.ITextLibraryTSAException;
import hu.signatures.samples.signandverifycommon.configuration.KeystoreConfiguration;
import hu.signatures.samples.signandverifycommon.configuration.ProxyConfiguration;
import hu.signatures.samples.signandverifycommon.configuration.TSAConfiguration;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.net.ssl.*;
import java.io.ByteArrayOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;

import static hu.signatures.samples.signandverifycommon.util.KeystoreUtils.loadKeystore;

@Slf4j
@Service
public class PdfSignatureMakerService {

    private final ProxyConfiguration proxyConfig;
    private final TSAConfiguration tsaConfiguration;
    private final KeystoreConfiguration keystoreConfiguration;
    private final SSLSocketFactory sslSocketFactory;
    private final KeyStore keystore;
    private final KeyStore tsaKeystore;

    public PdfSignatureMakerService(ProxyConfiguration proxyConfig, TSAConfiguration tsaConfiguration, KeystoreConfiguration keystoreConfiguration) {
        this.proxyConfig = proxyConfig;
        this.tsaConfiguration = tsaConfiguration;
        this.keystoreConfiguration = keystoreConfiguration;
        keystore = loadKeystore(keystoreConfiguration.getLocation(), keystoreConfiguration.getType(), keystoreConfiguration.getPassword());
        tsaKeystore = loadKeystore(tsaConfiguration.getKeystoreLocation(), tsaConfiguration.getKeystoreType(), tsaConfiguration.getKeystorePassword());
        this.sslSocketFactory = createSSLSocketFactory();
    }

    /**
     * Signs a PDF document using a specified key and optional TSA (Time-Stamp Authority).
     *
     * @param pdf         The input PDF document as a byte array.
     * @param keyAlias    The alias of the key from the keystore used for signing.
     * @param keyPassword The password for the key specified by keyAlias.
     * @param useTSA      Indicates whether to timestamp the signature (true for TSA, false otherwise).
     * @return A byte array representing the signed PDF document.
     */
    public byte[] signPdf(byte[] pdf, String keyAlias, String keyPassword, boolean useTSA) throws ITextLibraryTSAException {
        try (ByteArrayOutputStream pdfOut = new ByteArrayOutputStream()) {
            PdfReader reader = new PdfReader(pdf);
            PdfStamper stamper = PdfStamper.createSignature(reader, pdfOut, '\0', null, true);
            PdfSignatureAppearance appearance = stamper.getSignatureAppearance();

            ExternalSignature privateKeySignature = new PrivateKeySignature((PrivateKey) keystore.getKey(keyAlias, keyPassword.toCharArray()), keystoreConfiguration.getHashAlgorithm(), null);
            TSAClient tsaClient = useTSA ? new CustomTsaClient(proxyConfig, tsaConfiguration, this.sslSocketFactory) : null;

            MakeSignature.signDetached(appearance, new BouncyCastleDigest(), privateKeySignature, keystore.getCertificateChain(keyAlias), null, null, tsaClient, 0, MakeSignature.CryptoStandard.CMS);

            stamper.close();
            return pdfOut.toByteArray();
        } catch (Exception e) {
            Throwable cause = e.getCause();
            if (cause instanceof ITextLibraryTSAException) {
                throw (ITextLibraryTSAException) cause;
            }
            throw new ITextLibraryException("Error signing PDF", e);
        }
    }

    /**
     * Creates an SSLSocketFactory for secure communications using a custom SSL context.
     *
     * @return An SSLSocketFactory configured with a custom SSL context.
     * @throws ITextLibraryException if any errors occur while creating the SSLSocketFactory.
     */
    private SSLSocketFactory createSSLSocketFactory() {
        try {
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
            keyManagerFactory.init(tsaKeystore, tsaConfiguration.getKeystorePassword().toCharArray());
            KeyManager customKeyManager = new FixedAliasX509KeyManager(tsaConfiguration.getSslCertificateAlias(), (X509KeyManager) keyManagerFactory.getKeyManagers()[0]);
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(new KeyManager[]{customKeyManager}, null, null);
            return sslContext.getSocketFactory();
        } catch (Exception e) {
            throw new ITextLibraryException("Error creating SSLSocketFactory", e);
        }
    }
}

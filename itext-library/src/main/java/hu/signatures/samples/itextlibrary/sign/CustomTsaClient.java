package hu.signatures.samples.itextlibrary.sign;

import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.TSAClientBouncyCastle;
import hu.signatures.samples.itextlibrary.exception.ITextLibraryTSAException;
import hu.signatures.samples.itextlibrary.util.ConnectionUtils;
import hu.signatures.samples.signandverifycommon.configuration.ProxyConfiguration;
import hu.signatures.samples.signandverifycommon.configuration.TSAConfiguration;
import lombok.extern.slf4j.Slf4j;

import javax.net.ssl.SSLSocketFactory;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

@Slf4j
public class CustomTsaClient extends TSAClientBouncyCastle {
    private final ProxyConfiguration proxyConfig;
    private final TSAConfiguration tsaConfiguration;
    private final SSLSocketFactory sslSocketFactory;

    public CustomTsaClient(ProxyConfiguration proxyConfig, TSAConfiguration tsaConfiguration, SSLSocketFactory sslSocketFactory) {
        super(tsaConfiguration.getUrl(), tsaConfiguration.getUsername(), tsaConfiguration.getPassword());
        this.proxyConfig = proxyConfig;
        this.sslSocketFactory = sslSocketFactory;
        this.tsaConfiguration = tsaConfiguration;
        log.debug(String.format("CustomTsaClient initialized: url=%s; sslSocketFactory=%s;", tsaConfiguration.getUrl(),
                sslSocketFactory));
    }

    @Override
    public int getTokenSizeEstimate() {
        return this.tokenSizeEstimate;
    }

    @Override
    public MessageDigest getMessageDigest() throws GeneralSecurityException {
        return (new BouncyCastleDigest()).getMessageDigest(this.digestAlgorithm);
    }

    @Override
    protected byte[] getTSAResponse(byte[] requestBytes) throws ITextLibraryTSAException {
        return ConnectionUtils.getTSAResponse(requestBytes, tsaConfiguration, proxyConfig, sslSocketFactory);
    }
}

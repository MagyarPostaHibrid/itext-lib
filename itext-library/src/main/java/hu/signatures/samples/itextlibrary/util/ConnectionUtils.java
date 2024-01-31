package hu.signatures.samples.itextlibrary.util;

import com.itextpdf.text.pdf.codec.Base64;
import hu.signatures.samples.itextlibrary.exception.ITextLibraryTSAException;
import hu.signatures.samples.signandverifycommon.configuration.ProxyConfiguration;
import hu.signatures.samples.signandverifycommon.configuration.TSAConfiguration;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Hex;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;

/**
 * A utility class for managing connections and performing Time-Stamp Authority (TSA) operations.
 * This class provides methods for making TSA requests, handling HTTP(S) connections, and managing proxy settings.
 */
@Slf4j
public class ConnectionUtils {

    /**
     * Private constructor to prevent instantiation of this utility class.
     *
     * @throws IllegalStateException if an attempt is made to instantiate this utility class.
     */
    private ConnectionUtils() {
        throw new IllegalStateException("Utility class");
    }


    /**
     * Sends a TSA request to a TSA server and retrieves the TSA response.
     *
     * @param requestBytes     The TSA request data as a byte array.
     * @param tsaConfiguration        The TSA configuration specifying the server URL and credentials.
     * @param proxyConfiguration      The proxy configuration if used for the connection.
     * @param sslSocketFactory The SSLSocketFactory for secure connections.
     * @return A byte array containing the TSA response.
     * @throws ITextLibraryTSAException if any errors occur during the TSA request or response handling.
     */
    public static byte[] getTSAResponse(byte[] requestBytes, TSAConfiguration tsaConfiguration, ProxyConfiguration proxyConfiguration, SSLSocketFactory sslSocketFactory) throws ITextLibraryTSAException {
        try {
            HttpURLConnection tsaConnection = getConnection(tsaConfiguration.getUrl(), proxyConfiguration, sslSocketFactory);
            tsaConnection.setRequestMethod("POST");
            tsaConnection.setDoInput(true);
            tsaConnection.setDoOutput(true);
            tsaConnection.setUseCaches(false);

            tsaConnection.setRequestProperty("Content-Type", "application/timestamp-query");
            tsaConnection.setRequestProperty("Content-Transfer-Encoding", "binary");

            String tsaUsername = tsaConfiguration.getUsername();
            String tsaPassword = tsaConfiguration.getPassword();
            if ((tsaUsername != null) && !tsaUsername.isEmpty()) {
                String userPassword = tsaUsername + ":" + tsaPassword;
                tsaConnection.setRequestProperty("Authorization", "Basic " + Base64.encodeBytes(userPassword.getBytes(), Base64.DONT_BREAK_LINES));
            }

            try (OutputStream out = tsaConnection.getOutputStream()) {
                if (log.isTraceEnabled()) {
                    log.trace("TSA Request (HEX): " + Hex.toHexString(requestBytes));
                }
                out.write(requestBytes);
            }

            long startTime = System.currentTimeMillis();
            byte[] respBytes;
            try (InputStream inputStream = tsaConnection.getInputStream();
                 ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {
                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = inputStream.read(buffer, 0, buffer.length)) >= 0) {
                    byteArrayOutputStream.write(buffer, 0, bytesRead);
                }
                respBytes = byteArrayOutputStream.toByteArray();
            }

            log.debug("TSA response time (msec): " + (System.currentTimeMillis() - startTime));

            String encoding = tsaConnection.getContentEncoding();
            if (encoding != null && encoding.equalsIgnoreCase("base64")) {
                respBytes = Base64.decode(new String(respBytes));
            }
            if (log.isTraceEnabled()) {
                log.trace("TSA Response (HEX): " + Hex.toHexString(respBytes));
            }
            return respBytes;
        } catch (Exception e) {
            throw new ITextLibraryTSAException("TSA response error: " + e.getMessage());
        }
    }

    /**
     * Creates an HTTP or HTTPS connection to a specified URL, considering proxy settings and SSL configurations.
     *
     * @param strUrl           The URL to connect to.
     * @param proxyConfiguration      The proxy configuration, if any.
     * @param sslSocketFactory The SSLSocketFactory for secure connections.
     * @return A HttpURLConnection or HttpsURLConnection based on the URLs protocol.
     * @throws IOException if any errors occur during connection creation.
     */
    public static HttpURLConnection getConnection(String strUrl, ProxyConfiguration proxyConfiguration, SSLSocketFactory sslSocketFactory) throws IOException {
        URL url = new URL(strUrl);
        HttpURLConnection connection;

        String protocol = url.getProtocol();
        Proxy proxy = getHttpProxy(proxyConfiguration);
        if (protocol.equalsIgnoreCase("https")) {
            HttpsURLConnection sslConnection = (HttpsURLConnection) (proxy == null ? url.openConnection() : url.openConnection(proxy));
            if (sslSocketFactory != null) {
                sslConnection.setSSLSocketFactory(sslSocketFactory);
            }
            connection = sslConnection;
        } else {
            connection = (HttpURLConnection) (proxy == null ? url.openConnection() : url.openConnection(proxy));
        }
        if (proxy != null) {
            setProxyAuthentication(connection, proxyConfiguration);
        }
        if (log.isTraceEnabled()) {
            if (proxy == null) {
                log.trace(String.format("%s connection create from url '%s'", protocol, strUrl));
            } else {
                log.trace(String.format("%s connection create from url '%s' with proxy %s", protocol, strUrl, proxyConfiguration));
            }
        }
        return connection;
    }

    /**
     * Converts a ProxyConfig object into a Java Proxy object for use in connections.
     *
     * @param proxyConfiguration The ProxyConfig containing proxy settings.
     * @return A Proxy object representing the HTTP proxy if configured; otherwise, null.
     */
    private static Proxy getHttpProxy(ProxyConfiguration proxyConfiguration) {
        if (proxyConfiguration == null) {
            return null;
        }
        if (proxyConfiguration.getHost() == null || proxyConfiguration.getHost().isEmpty()) {
            return null;
        }
        return new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyConfiguration.getHost(), Integer.parseInt(proxyConfiguration.getPort())));
    }

    /**
     * Sets proxy authentication headers for an HttpURLConnection based on proxy configuration.
     *
     * @param connection  The HttpURLConnection object to set proxy authentication headers for.
     * @param proxyConfiguration The proxy configuration containing user and password information.
     */
    private static void setProxyAuthentication(HttpURLConnection connection, ProxyConfiguration proxyConfiguration) {
        if (proxyConfiguration.getUser() == null || proxyConfiguration.getUser().isEmpty()) {
            return;
        }
        connection.setRequestProperty("Proxy-Authorization", "Basic " + Base64.encodeBytes((proxyConfiguration.getUser() + ":" + proxyConfiguration.getPassword()).getBytes()));
    }
}

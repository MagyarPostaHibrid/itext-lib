package hu.signatures.samples.itextlibrary.sign;

import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * A custom implementation of X509ExtendedKeyManager that ensures a fixed alias is used for SSL key management.
 * This class delegates most key management operations to another X509KeyManager while always returning a fixed alias
 * when requested, ensuring that a specific alias is consistently used for SSL operations.
 * This class is designed to be used in scenarios where you need to enforce the use of a specific key alias for SSL
 * communication, regardless of the circumstances.
 *
 * @see X509ExtendedKeyManager
 */
public class FixedAliasX509KeyManager extends X509ExtendedKeyManager {

    private final String alias;
    private final X509KeyManager delegate;

    /**
     * Constructs a FixedAliasX509KeyManager with a fixed alias and a delegate X509KeyManager.
     *
     * @param alias    The fixed alias to be used for SSL key management operations.
     * @param delegate The delegate X509KeyManager to which key management operations are delegated.
     */
    public FixedAliasX509KeyManager(String alias, X509KeyManager delegate) {
        this.alias = alias;
        this.delegate = delegate;
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return new String[]{alias};
    }

    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        return alias;
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return delegate.getServerAliases(keyType, issuers);
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        return delegate.chooseServerAlias(keyType, issuers, socket);
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        return delegate.getCertificateChain(alias);
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
        return delegate.getPrivateKey(alias);
    }
}

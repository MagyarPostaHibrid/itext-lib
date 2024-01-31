package hu.signatures.samples.signandverifycommon.configuration;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "proxy")
public class ProxyConfiguration {
    private String host;
    private String port;
    private String user;
    private String password;
    private boolean enableHttpProxy;
    private boolean enableHttpsProxy;


    public boolean isConfigured() {
        return this.host != null && !this.host.isEmpty();
    }

    @Override
    public String toString() {
        if (isConfigured()) {
            return host + ":" + port;
        }
        return "NO_PROXY";
    }
}

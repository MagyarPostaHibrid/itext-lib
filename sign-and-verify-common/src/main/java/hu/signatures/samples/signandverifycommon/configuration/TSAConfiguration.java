package hu.signatures.samples.signandverifycommon.configuration;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "tsa")
public class TSAConfiguration {
    private String url;
    private String keystoreLocation;
    private String keystorePassword;
    private String keystoreType;
    private String username;
    private String password;
    private String sslCertificateAlias;
}

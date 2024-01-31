package hu.signatures.samples.signandverifycommon.configuration;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "keystore")
public class KeystoreConfiguration {
    private String location;
    private String password;
    private String type;
    private String hashAlgorithm;
}

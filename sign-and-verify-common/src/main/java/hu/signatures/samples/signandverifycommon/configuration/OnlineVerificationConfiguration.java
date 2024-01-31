package hu.signatures.samples.signandverifycommon.configuration;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "online")
public class OnlineVerificationConfiguration {
    private boolean ocspValidationDisabled;
    private boolean crlOnlineValidationDisabled;
    private String crlListLocation;
}

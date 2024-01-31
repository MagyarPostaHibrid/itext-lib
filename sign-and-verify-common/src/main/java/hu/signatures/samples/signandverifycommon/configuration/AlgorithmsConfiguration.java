package hu.signatures.samples.signandverifycommon.configuration;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;

@Getter
@Setter
@ConfigurationProperties(prefix = "evid-gen-sign-and-verify")
public class AlgorithmsConfiguration {
    private List<Algorithm> algorithms;

    @Getter
    @Setter
    public static class Algorithm{
        private String name;
        private String oid;
        private String rfcName;
    }
}

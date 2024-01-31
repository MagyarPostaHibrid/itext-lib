package hu.signatures.samples.signandverifycommon.configuration;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties({TSAConfiguration.class, ProxyConfiguration.class, KeystoreConfiguration.class, TruststoreConfiguration.class, OnlineVerificationConfiguration.class, AlgorithmsConfiguration.class})
public class CommonConfiguration {
}

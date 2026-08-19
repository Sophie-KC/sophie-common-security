package org.sophie.security.autoconfigure;

import org.sophie.security.comparison.IdentityComparisonLogger;
import org.sophie.security.context.DefaultPrincipalAccessor;
import org.sophie.security.context.PrincipalAccessor;
import org.sophie.security.jwt.JwtVerifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * Base auto-configuration: the JWT verifier, the comparison logger, and the principal accessor bean.
 * Neither of the two gRPC-side auto-configurations ({@link SophieSecurityServerAutoConfiguration},
 * {@link SophieSecurityClientAutoConfiguration}) can run without these, so they're split out here and
 * ordered ahead via {@code @AutoConfigureAfter} on those two.
 */
@AutoConfiguration
@EnableConfigurationProperties(SophieSecurityProperties.class)
public class SophieSecurityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public JwtVerifier sophieJwtVerifier(
            @Value("${keycloak.jwt.jwk-set-uri}") String jwkSetUri,
            @Value("${keycloak.jwt.issuer-uri}") String issuerUri) {
        return new JwtVerifier(jwkSetUri, issuerUri);
    }

    @Bean
    @ConditionalOnMissingBean
    public IdentityComparisonLogger identityComparisonLogger(SophieSecurityProperties props) {
        return new IdentityComparisonLogger(props.getServiceName());
    }

    @Bean
    @ConditionalOnMissingBean
    public PrincipalAccessor principalAccessor() {
        return new DefaultPrincipalAccessor();
    }
}

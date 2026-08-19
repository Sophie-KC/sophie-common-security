package org.sophie.security.autoconfigure;

import org.sophie.security.comparison.IdentityComparisonLogger;
import org.sophie.security.context.DefaultPrincipalAccessor;
import org.sophie.security.context.PrincipalAccessor;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * Base auto-configuration: the comparison logger and the principal accessor bean, needed regardless of
 * whether this service has a gRPC server, a client, or both. The {@code JwtVerifier} bean itself lives
 * in {@link SophieSecurityServerAutoConfiguration} instead — a client-only service (e.g.
 * websocket-service) never verifies an inbound JWT, so it shouldn't need {@code keycloak.jwt.*}
 * configured at all just to satisfy a bean it never uses.
 */
@AutoConfiguration
@EnableConfigurationProperties(SophieSecurityProperties.class)
public class SophieSecurityAutoConfiguration {

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

package org.sophie.security.autoconfigure;

import io.grpc.ServerInterceptor;
import net.devh.boot.grpc.server.interceptor.GrpcGlobalServerInterceptor;
import org.sophie.security.comparison.IdentityComparisonLogger;
import org.sophie.security.grpc.JwtServerInterceptor;
import org.sophie.security.jwt.JwtVerifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;

/**
 * No-ops (never even loaded past condition evaluation) on services with no gRPC server — api-gateway,
 * websocket-service — via {@code @ConditionalOnClass}, which Spring evaluates by reading bytecode
 * metadata before actually loading this class, so a missing net.devh server dependency never throws.
 * {@code keycloak.jwt.*} is therefore only required on services this configuration actually activates
 * on.
 */
@AutoConfiguration
@AutoConfigureAfter(SophieSecurityAutoConfiguration.class)
@ConditionalOnClass(name = "net.devh.boot.grpc.server.interceptor.GrpcGlobalServerInterceptor")
public class SophieSecurityServerAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public JwtVerifier sophieJwtVerifier(
            @Value("${keycloak.jwt.jwk-set-uri}") String jwkSetUri,
            @Value("${keycloak.jwt.issuer-uri}") String issuerUri) {
        return new JwtVerifier(jwkSetUri, issuerUri);
    }

    @Bean
    @GrpcGlobalServerInterceptor
    @Order(Ordered.HIGHEST_PRECEDENCE + 10)
    public ServerInterceptor sophieJwtServerInterceptor(
            JwtVerifier jwtVerifier,
            SophieSecurityProperties props,
            IdentityComparisonLogger comparisonLogger) {
        return new JwtServerInterceptor(jwtVerifier, props.getInternal().getSharedSecret(), comparisonLogger);
    }
}

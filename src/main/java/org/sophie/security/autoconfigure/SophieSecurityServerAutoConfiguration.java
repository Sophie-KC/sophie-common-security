package org.sophie.security.autoconfigure;

import io.grpc.ServerInterceptor;
import net.devh.boot.grpc.server.interceptor.GrpcGlobalServerInterceptor;
import org.sophie.security.comparison.IdentityComparisonLogger;
import org.sophie.security.grpc.JwtServerInterceptor;
import org.sophie.security.jwt.JwtVerifier;
import org.sophie.security.policy.PrincipalTierPolicy;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
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

    /** Default matches the {@code sophie-api} audience protocol mapper applied to every
     *  token-minting client (web-app, mobile-app, test-client) in {@code sophie-infra}'s Keycloak
     *  Terraform module — see {@code modules/keycloak/clients.tf}. Overridable per service via
     *  {@code keycloak.jwt.expected-audience} only for a service with a genuinely different need;
     *  there isn't one today.
     *
     * <p>{@code @ConditionalOnMissingBean(name = "sophieJwtVerifier")}, NOT the bare, by-type form:
     * org-service now also defines a second, differently-purposed {@code JwtVerifier} bean
     * ({@code staffJwtVerifier}, for the isolated staff realm — see {@code StaffJwtVerifierConfig}).
     * A by-type {@code @ConditionalOnMissingBean} would see that unrelated bean, conclude "a
     * JwtVerifier already exists," and skip creating this one entirely — leaving the interceptor's
     * primary {@code jwtVerifier} parameter with no real candidate except the staff bean, silently
     * misrouting every customer-realm token through the staff JWKS. Scoping by name means only a
     * service that defines its own bean NAMED {@code sophieJwtVerifier} (overriding this one on
     * purpose) suppresses it; an unrelated same-typed bean like {@code staffJwtVerifier} no longer can. */
    @Bean
    @ConditionalOnMissingBean(name = "sophieJwtVerifier")
    public JwtVerifier sophieJwtVerifier(
            @Value("${keycloak.jwt.jwk-set-uri}") String jwkSetUri,
            @Value("${keycloak.jwt.issuer-uri}") String issuerUri,
            @Value("${keycloak.jwt.expected-audience:sophie-api}") String expectedAudience) {
        return new JwtVerifier(jwkSetUri, issuerUri, expectedAudience);
    }

    /**
     * {@code tierPolicyProvider} is optional: a service that hasn't defined a {@link PrincipalTierPolicy}
     * bean gets {@code null} here, and every RPC then falls back to {@link PrincipalTierPolicy#DEFAULT_TIER}
     * inside the interceptor — enforcing still works, just without any allowlisted exceptions.
     *
     * <p>{@code staffJwtVerifierProvider} is likewise optional, and by NAME rather than type (a plain
     * {@code ObjectProvider<JwtVerifier>} would be ambiguous the moment two {@code JwtVerifier} beans
     * exist at all) — null everywhere except a service that defines its own {@code JwtVerifier} bean
     * named exactly {@code "staffJwtVerifier"} (org-service today, for its admin surface). Every other
     * service's interceptor is byte-for-byte what it was before this parameter existed.
     *
     * <p>{@code jwtVerifier} is likewise explicitly qualified by name ({@code "sophieJwtVerifier"},
     * matching {@link #sophieJwtVerifier}'s bean name) now that a service can define a second
     * {@code JwtVerifier} bean — without this, plain by-type injection would throw
     * {@code NoUniqueBeanDefinitionException} on org-service the moment both beans exist.
     */
    @Bean
    @GrpcGlobalServerInterceptor
    @Order(Ordered.HIGHEST_PRECEDENCE + 10)
    public ServerInterceptor sophieJwtServerInterceptor(
            @Qualifier("sophieJwtVerifier") JwtVerifier jwtVerifier,
            SophieSecurityProperties props,
            IdentityComparisonLogger comparisonLogger,
            ObjectProvider<PrincipalTierPolicy> tierPolicyProvider,
            @Qualifier("staffJwtVerifier") ObjectProvider<JwtVerifier> staffJwtVerifierProvider) {
        return new JwtServerInterceptor(jwtVerifier, staffJwtVerifierProvider.getIfAvailable(),
                props.getInternal().getSharedSecret(), comparisonLogger,
                props.isEnforce(), tierPolicyProvider.getIfAvailable());
    }
}

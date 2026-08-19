package org.sophie.security.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.util.Set;

/**
 * Verifies a compact JWT's signature against a Keycloak realm's JWKS. Built directly on Nimbus (the
 * same library Spring Security's NimbusJwtDecoder wraps internally) rather than depending on Spring
 * Security at all — that keeps spring-security-web/config off every consumer's classpath entirely, so
 * this library can never activate Spring Boot's default HTTP security auto-configuration on services
 * that run webmvc solely to serve the actuator health endpoint.
 *
 * <p>JWKS keys are fetched once and cached in memory ({@code JWKSourceBuilder}'s own cache, refreshed
 * automatically on an unrecognized key id) — verification is a local signature check with no
 * per-request network call, and Keycloak being unreachable does not affect already-running services.
 */
public class JwtVerifier {

    private final ConfigurableJWTProcessor<SecurityContext> processor;

    public JwtVerifier(String jwkSetUri, String issuer) {
        try {
            JWKSource<SecurityContext> jwkSource = JWKSourceBuilder
                    .create(new URL(jwkSetUri))
                    .cache(true)
                    .build();
            DefaultJWTProcessor<SecurityContext> p = new DefaultJWTProcessor<>();
            p.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, jwkSource));
            p.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(
                    new JWTClaimsSet.Builder().issuer(issuer).build(),
                    Set.of("sub", "exp")));
            this.processor = p;
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException("Invalid keycloak.jwt.jwk-set-uri: " + jwkSetUri, e);
        }
    }

    /** Returns verified claims, or throws if the signature, issuer, or expiry don't check out. */
    public JWTClaimsSet verify(String compactJwt) throws ParseException, JOSEException, BadJOSEException {
        return processor.process(compactJwt, null);
    }
}

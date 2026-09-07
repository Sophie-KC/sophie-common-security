package org.sophie.security.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
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
    private final String expectedAudience;

    /** @deprecated use {@link #JwtVerifier(String, String, String)} — this overload validates no
     *  audience at all, which lets a token minted for any Keycloak client in the realm (including
     *  one this service never expects to hear from) pass verification here. Kept only so a caller
     *  that genuinely cannot supply an audience yet doesn't fail to compile. */
    @Deprecated
    public JwtVerifier(String jwkSetUri, String issuer) {
        this(jwkSetUri, issuer, null);
    }

    /**
     * @param expectedAudience required {@code aud} value, or {@code null}/blank to skip audience
     *                         validation entirely (not recommended — see the deprecated overload).
     *                         Checked manually after Nimbus's own claim verification rather than via
     *                         {@link DefaultJWTClaimsVerifier}'s {@code aud} exact-match slot — that
     *                         slot requires the token's ENTIRE audience list to equal exactly
     *                         {@code [expectedAudience]}, which every real Keycloak-issued token
     *                         fails outright (Keycloak always adds its own built-in {@code account}
     *                         audience alongside any custom one via its default audience mapper).
     *                         What's actually wanted — and what api-gateway's own separate
     *                         {@code JwtConfig} validator already correctly does — is "the audience
     *                         list CONTAINS the expected value," so that's checked directly here.
     */
    public JwtVerifier(String jwkSetUri, String issuer, String expectedAudience) {
        this.expectedAudience = (expectedAudience != null && !expectedAudience.isBlank()) ? expectedAudience : null;
        try {
            JWKSource<SecurityContext> jwkSource = JWKSourceBuilder
                    .create(new URL(jwkSetUri))
                    .cache(true)
                    .build();
            DefaultJWTProcessor<SecurityContext> p = new DefaultJWTProcessor<>();
            p.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, jwkSource));
            JWTClaimsSet.Builder exactMatch = new JWTClaimsSet.Builder().issuer(issuer);
            p.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(exactMatch.build(), Set.of("sub", "exp")));
            this.processor = p;
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException("Invalid keycloak.jwt.jwk-set-uri: " + jwkSetUri, e);
        }
    }

    /** Returns verified claims, or throws if the signature, issuer, expiry, or (when configured)
     *  audience don't check out. */
    public JWTClaimsSet verify(String compactJwt) throws ParseException, JOSEException, BadJOSEException {
        JWTClaimsSet claims = processor.process(compactJwt, null);
        if (expectedAudience != null && !claims.getAudience().contains(expectedAudience)) {
            throw new BadJWTException("JWT aud claim " + claims.getAudience() + " does not contain " + expectedAudience);
        }
        return claims;
    }
}

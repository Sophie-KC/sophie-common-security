package org.sophie.security.jwt;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.Date;
import java.util.List;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Exercises {@link JwtVerifier}'s audience check end to end against a real signature — a throwaway
 * in-process HTTP server serves the JWKS (no live Keycloak needed) and a real RSA-signed JWT is
 * built with Nimbus directly. Complements {@code JwtConfigAudienceValidatorTest} in api-gateway,
 * which covers the equivalent (but library-less) validator there.
 */
class JwtVerifierAudienceTest {

    private static final String ISSUER = "http://localhost/realms/team-collab-platform-local";
    private static final String EXPECTED_AUDIENCE = "sophie-api";

    private RSAKey rsaKey;
    private HttpServer jwksServer;
    private String jwkSetUri;

    @BeforeEach
    void setUp() throws Exception {
        rsaKey = new RSAKeyGenerator(2048).keyID("test-key").generate();

        jwksServer = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        jwksServer.createContext("/certs", exchange -> {
            byte[] body = new JWKSet(rsaKey.toPublicJWK()).toString().getBytes();
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(body);
            }
        });
        jwksServer.start();
        jwkSetUri = "http://localhost:" + jwksServer.getAddress().getPort() + "/certs";
    }

    @AfterEach
    void tearDown() {
        jwksServer.stop(0);
    }

    @Test
    void tokenWithExpectedAudiencePasses() throws Exception {
        JwtVerifier verifier = new JwtVerifier(jwkSetUri, ISSUER, EXPECTED_AUDIENCE);

        String token = signedToken(List.of(EXPECTED_AUDIENCE));

        assertDoesNotThrow(() -> verifier.verify(token));
    }

    @Test
    void tokenWithExpectedAudiencePlusKeycloaksOwnDefaultAudiencePasses() throws Exception {
        // Regression test: every real Keycloak-issued token carries its own built-in "account"
        // audience alongside any custom one (the default audience mapper), e.g. aud=[sophie-api,
        // account]. Nimbus's DefaultJWTClaimsVerifier "aud" exact-match slot requires the ENTIRE
        // list to equal exactly [expectedAudience] and rejects this outright — caught only by
        // testing a real multi-valued audience list, which the single-audience test above cannot
        // catch. Fixed by checking "audience list contains expectedAudience" manually instead.
        JwtVerifier verifier = new JwtVerifier(jwkSetUri, ISSUER, EXPECTED_AUDIENCE);

        String token = signedToken(List.of(EXPECTED_AUDIENCE, "account"));

        assertDoesNotThrow(() -> verifier.verify(token));
    }

    @Test
    void tokenWithNoAudienceIsRejected() throws Exception {
        JwtVerifier verifier = new JwtVerifier(jwkSetUri, ISSUER, EXPECTED_AUDIENCE);

        String token = signedToken(null);

        assertThrows(Exception.class, () -> verifier.verify(token));
    }

    @Test
    void tokenWithMismatchedAudienceIsRejected() throws Exception {
        JwtVerifier verifier = new JwtVerifier(jwkSetUri, ISSUER, EXPECTED_AUDIENCE);

        String token = signedToken(List.of("some-other-client"));

        assertThrows(Exception.class, () -> verifier.verify(token));
    }

    @Test
    void deprecatedTwoArgConstructorSkipsAudienceValidationEntirely() throws Exception {
        @SuppressWarnings("deprecation")
        JwtVerifier verifier = new JwtVerifier(jwkSetUri, ISSUER);

        // No audience at all still passes — documents the deprecated overload's exact behavior
        // rather than leaving it as an untested footgun.
        String token = signedToken(null);

        assertDoesNotThrow(() -> verifier.verify(token));
    }

    private String signedToken(List<String> audience) throws Exception {
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                .subject("test-subject")
                .issuer(ISSUER)
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + 60_000));
        if (audience != null) {
            claims.audience(audience);
        }
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey.getKeyID()).build(), claims.build());
        jwt.sign(new RSASSASigner(rsaKey));
        return jwt.serialize();
    }
}

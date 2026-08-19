package org.sophie.security.grpc;

import com.nimbusds.jwt.JWTClaimsSet;
import io.grpc.Context;
import io.grpc.Contexts;
import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sophie.security.comparison.IdentityComparisonLogger;
import org.sophie.security.context.SophieSecurityContext;
import org.sophie.security.jwt.JwtVerifier;
import org.sophie.security.principal.AssertedUserPrincipal;
import org.sophie.security.principal.ServicePrincipal;
import org.sophie.security.principal.SophiePrincipal;
import org.sophie.security.principal.UserPrincipal;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Validates the caller's bearer JWT (or, absent one, the internal shared secret) and populates a
 * {@link SophiePrincipal} on the gRPC {@link Context}. Non-enforcing by design: any verification
 * failure or outright absence just proceeds with no principal — see {@link IdentityComparisonLogger}
 * for what surfaces that fact. This interceptor never rejects a call.
 */
public class JwtServerInterceptor implements ServerInterceptor {

    private static final Logger log = LoggerFactory.getLogger(JwtServerInterceptor.class);

    static final Metadata.Key<String> AUTHORIZATION =
            Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER);
    static final Metadata.Key<String> INTERNAL_SECRET =
            Metadata.Key.of("x-internal-service-secret", Metadata.ASCII_STRING_MARSHALLER);
    static final Metadata.Key<String> INTERNAL_SERVICE_NAME =
            Metadata.Key.of("x-internal-service-name", Metadata.ASCII_STRING_MARSHALLER);
    static final Metadata.Key<String> USER_ID =
            Metadata.Key.of("x-user-id", Metadata.ASCII_STRING_MARSHALLER);
    static final Metadata.Key<String> ORG_ROLE =
            Metadata.Key.of("x-org-role", Metadata.ASCII_STRING_MARSHALLER);
    static final Metadata.Key<String> ASSERTED_USER_ID =
            Metadata.Key.of("x-asserted-internal-user-id", Metadata.ASCII_STRING_MARSHALLER);
    static final Metadata.Key<String> ASSERTED_KEYCLOAK_SUB =
            Metadata.Key.of("x-asserted-keycloak-sub", Metadata.ASCII_STRING_MARSHALLER);

    private final JwtVerifier jwtVerifier;
    private final String expectedInternalSecret;
    private final IdentityComparisonLogger comparisonLogger;

    public JwtServerInterceptor(JwtVerifier jwtVerifier, String expectedInternalSecret,
            IdentityComparisonLogger comparisonLogger) {
        this.jwtVerifier = jwtVerifier;
        this.expectedInternalSecret = expectedInternalSecret;
        this.comparisonLogger = comparisonLogger;
    }

    @Override
    public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(
            ServerCall<ReqT, RespT> call, Metadata headers, ServerCallHandler<ReqT, RespT> next) {

        String methodName = call.getMethodDescriptor().getFullMethodName();
        SophiePrincipal principal = null;
        String rawToken = null;

        String authHeader = headers.get(AUTHORIZATION);
        if (authHeader != null && authHeader.regionMatches(true, 0, "Bearer ", 0, 7)) {
            rawToken = authHeader.substring(7).trim();
            try {
                JWTClaimsSet claims = jwtVerifier.verify(rawToken);
                String internalUserId = claims.getStringClaim("internal_user_id");
                principal = new UserPrincipal(claims.getSubject(), internalUserId, rawToken);
            } catch (Exception e) {
                log.warn("JWT verification failed for {}: {}", methodName, e.toString());
                rawToken = null;
            }
        } else {
            String secret = headers.get(INTERNAL_SECRET);
            if (secret != null && expectedInternalSecret != null && !expectedInternalSecret.isBlank()
                    && constantTimeEquals(secret, expectedInternalSecret)) {
                String serviceName = headers.get(INTERNAL_SERVICE_NAME);
                String assertedUserId = headers.get(ASSERTED_USER_ID);
                if (assertedUserId != null && !assertedUserId.isBlank()) {
                    principal = new AssertedUserPrincipal(
                            serviceName != null ? serviceName : "unknown",
                            headers.get(ASSERTED_KEYCLOAK_SUB),
                            assertedUserId);
                } else {
                    principal = new ServicePrincipal(serviceName != null ? serviceName : "unknown");
                }
            } else if (secret != null) {
                log.warn("Internal service secret mismatch on {}", methodName);
            }
        }

        String suppliedUserId = headers.get(USER_ID);
        String suppliedOrgRole = headers.get(ORG_ROLE);

        comparisonLogger.compare(methodName, principal, suppliedUserId);

        Context context = Context.current().withValue(SophieSecurityContext.PRINCIPAL, principal);
        if (rawToken != null) {
            context = context.withValue(SophieSecurityContext.RAW_TOKEN, rawToken);
        }
        if (suppliedUserId != null) {
            context = context.withValue(SophieSecurityContext.FORWARDED_USER_ID, suppliedUserId);
        }
        if (suppliedOrgRole != null) {
            context = context.withValue(SophieSecurityContext.FORWARDED_ORG_ROLE, suppliedOrgRole);
        }
        if (principal instanceof AssertedUserPrincipal aup) {
            context = context.withValue(SophieSecurityContext.ASSERTED_INTERNAL_USER_ID, aup.internalUserId());
            if (aup.keycloakSub() != null) {
                context = context.withValue(SophieSecurityContext.ASSERTED_KEYCLOAK_SUB, aup.keycloakSub());
            }
        }

        return Contexts.interceptCall(context, call, headers, next);
    }

    private static boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }
}

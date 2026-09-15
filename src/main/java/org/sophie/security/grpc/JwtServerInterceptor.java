package org.sophie.security.grpc;

import com.nimbusds.jwt.JWTClaimsSet;
import io.grpc.Context;
import io.grpc.Contexts;
import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.Status;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sophie.security.comparison.IdentityComparisonLogger;
import org.sophie.security.context.SophieSecurityContext;
import org.sophie.security.jwt.JwtVerifier;
import org.sophie.security.policy.PrincipalTier;
import org.sophie.security.policy.PrincipalTierPolicy;
import org.sophie.security.principal.AssertedUserPrincipal;
import org.sophie.security.principal.ServicePrincipal;
import org.sophie.security.principal.SophiePrincipal;
import org.sophie.security.principal.StaffPrincipal;
import org.sophie.security.principal.UserPrincipal;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Validates the caller's bearer JWT (or, absent one, the internal shared secret) and populates a
 * {@link SophiePrincipal} on the gRPC {@link Context}.
 *
 * <p>Non-enforcing by default: any verification failure or outright absence just proceeds with no
 * principal — see {@link IdentityComparisonLogger} for what surfaces that fact. When {@code enforce}
 * is true, a call with no verifiable identity is rejected {@code UNAUTHENTICATED}, and a call whose
 * principal is weaker than the RPC's {@link PrincipalTierPolicy} requirement is rejected
 * {@code PERMISSION_DENIED} — before the call ever reaches the service implementation.
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

    // Keycloak's own always-present realm roles — never a real staff assignment, so they're excluded
    // when picking "the" role out of a staff token's realm_access.roles claim. Kept generic (no
    // PLATFORM_ADMIN/BILLING_STAFF/SUPPORT string here) so this shared library never has to know the
    // specific staff role names a consuming service invents.
    private static final Set<String> KEYCLOAK_BUILTIN_ROLES = Set.of("offline_access", "uma_authorization");

    private final JwtVerifier jwtVerifier;
    private final JwtVerifier staffJwtVerifier;
    private final String expectedInternalSecret;
    private final IdentityComparisonLogger comparisonLogger;
    private final boolean enforce;
    private final PrincipalTierPolicy tierPolicy;

    public JwtServerInterceptor(JwtVerifier jwtVerifier, String expectedInternalSecret,
            IdentityComparisonLogger comparisonLogger) {
        this(jwtVerifier, expectedInternalSecret, comparisonLogger, false, null);
    }

    public JwtServerInterceptor(JwtVerifier jwtVerifier, String expectedInternalSecret,
            IdentityComparisonLogger comparisonLogger, boolean enforce, PrincipalTierPolicy tierPolicy) {
        this(jwtVerifier, null, expectedInternalSecret, comparisonLogger, enforce, tierPolicy);
    }

    /**
     * @param staffJwtVerifier optional second verifier for an isolated staff Keycloak realm — null
     *                         for every service that has no staff-facing RPCs at all (i.e. everyone
     *                         except org-service today). Tried only when {@code jwtVerifier} (the
     *                         customer realm) rejects the token outright, never both — a token is
     *                         from exactly one realm.
     */
    public JwtServerInterceptor(JwtVerifier jwtVerifier, JwtVerifier staffJwtVerifier, String expectedInternalSecret,
            IdentityComparisonLogger comparisonLogger, boolean enforce, PrincipalTierPolicy tierPolicy) {
        this.jwtVerifier = jwtVerifier;
        this.staffJwtVerifier = staffJwtVerifier;
        this.expectedInternalSecret = expectedInternalSecret;
        this.comparisonLogger = comparisonLogger;
        this.enforce = enforce;
        this.tierPolicy = tierPolicy;
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
            } catch (Exception primaryFailure) {
                // A token from the isolated staff realm always fails the customer-realm verifier
                // outright (wrong issuer) — that's the expected, non-error path here, not a fallback
                // from a broken primary token. Only actually try it when a staff verifier is even
                // configured (org-service today; null everywhere else, matching every existing
                // deployment with zero behavior change).
                if (staffJwtVerifier != null) {
                    try {
                        JWTClaimsSet staffClaims = staffJwtVerifier.verify(rawToken);
                        principal = new StaffPrincipal(staffClaims.getSubject(), extractStaffRole(staffClaims), rawToken);
                    } catch (Exception staffFailure) {
                        log.warn("JWT verification failed for {} against both the customer and staff realms: {} / {}",
                                methodName, primaryFailure.toString(), staffFailure.toString());
                        rawToken = null;
                    }
                } else {
                    log.warn("JWT verification failed for {}: {}", methodName, primaryFailure.toString());
                    rawToken = null;
                }
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

        if (enforce) {
            PrincipalTier actualTier = PrincipalTier.of(principal);
            if (actualTier == null) {
                call.close(Status.UNAUTHENTICATED.withDescription(
                        "No verified identity presented for " + methodName), new Metadata());
                return new ServerCall.Listener<>() {};
            }
            PrincipalTier requiredTier = tierPolicy != null ? tierPolicy.requiredTier(methodName) : null;
            if (requiredTier == null) {
                requiredTier = PrincipalTierPolicy.DEFAULT_TIER;
            }
            if (actualTier.ordinal() < requiredTier.ordinal()) {
                call.close(Status.PERMISSION_DENIED.withDescription(
                        methodName + " requires " + requiredTier + ", caller presented " + actualTier),
                        new Metadata());
                return new ServerCall.Listener<>() {};
            }
        }

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

    /** The one real role out of the staff realm's {@code realm_access.roles} claim, filtering out
     *  Keycloak's own always-present built-ins (see {@link #KEYCLOAK_BUILTIN_ROLES}) and the
     *  {@code default-roles-<realm>} composite every realm mints automatically. Null if none remain —
     *  a staff account provisioned with no role assigned yet, which the caller must treat as
     *  unauthorized, never as "figure out a default." */
    private static String extractStaffRole(JWTClaimsSet claims) {
        try {
            Map<String, Object> realmAccess = claims.getJSONObjectClaim("realm_access");
            if (realmAccess == null || !(realmAccess.get("roles") instanceof List<?> roles)) {
                return null;
            }
            return roles.stream()
                    .filter(String.class::isInstance)
                    .map(String.class::cast)
                    .filter(role -> !KEYCLOAK_BUILTIN_ROLES.contains(role) && !role.startsWith("default-roles-"))
                    .findFirst()
                    .orElse(null);
        } catch (java.text.ParseException e) {
            return null;
        }
    }
}

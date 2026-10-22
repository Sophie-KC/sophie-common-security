package org.sophie.security.comparison;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sophie.security.principal.AssertedUserPrincipal;
import org.sophie.security.principal.ServicePrincipal;
import org.sophie.security.principal.SophiePrincipal;
import org.sophie.security.principal.StaffPrincipal;
import org.sophie.security.principal.UserPrincipal;

/**
 * Logs identity-propagation signal for every call — the deliverable of phase 1. This measures whether
 * verified identity matches what the caller supplied via {@code x-user-id}, NOT authorization
 * correctness: a call that's already correctly scoped via a differently-named field (e.g.
 * {@code HasScopeAccessRequest.user_id}) still logs as "not propagated" here, which is accurate and is
 * exactly the phase-2 work list this exists to produce, not a false positive.
 *
 * <p>Every line carries a {@code principalKind} — {@code JWT_USER} (Keycloak-signature-verified),
 * {@code ASSERTED_USER} (vouched for by a trusted internal service, weaker — see {@link
 * AssertedUserPrincipal}), or {@code SERVICE} — so the two user-shaped trust tiers stay distinguishable
 * in logs even though both compare against the supplied {@code x-user-id} the same way.
 */
public class IdentityComparisonLogger {

    private static final Logger log = LoggerFactory.getLogger("org.sophie.security.IdentityComparison");

    private final String serviceName;

    public IdentityComparisonLogger(String serviceName) {
        this.serviceName = serviceName;
    }

    /**
     * True only for the one signal that always means impersonation: a user-shaped verified principal
     * whose resolved internal id is present, a supplied {@code x-user-id} that is also present, and the
     * two differ. The gateway always forwards {@code x-user-id} derived from the same verified token, so
     * a divergence cannot arise from a legitimate caller — only from a header forged by something other
     * than the gateway (e.g. a backend peer on the flat internal network). Absent/unresolved ids and
     * Service/Staff principals are never a mismatch (a call correctly scoped via a differently-named
     * field legitimately carries no {@code x-user-id}). Callers reject this under {@code enforce}; it is
     * deliberately narrower than the WARN logging in {@link #compare}, which also flags non-propagation.
     */
    public static boolean isForgedUserIdMismatch(SophiePrincipal verified, String suppliedUserId) {
        if (verified == null || suppliedUserId == null || suppliedUserId.isBlank()) {
            return false;
        }
        String internalUserId = switch (verified) {
            case UserPrincipal up -> up.internalUserId();
            case AssertedUserPrincipal aup -> aup.internalUserId();
            default -> null;
        };
        return internalUserId != null && !internalUserId.isBlank() && !internalUserId.equals(suppliedUserId);
    }

    public void compare(String rpcMethod, SophiePrincipal verified, String suppliedUserId) {
        boolean suppliedPresent = suppliedUserId != null && !suppliedUserId.isBlank();

        if (verified == null) {
            if (suppliedPresent) {
                log.warn("reason=NO_VERIFIABLE_IDENTITY service={} rpc={} supplied={}", serviceName, rpcMethod, suppliedUserId);
            } else {
                log.debug("reason=FULLY_UNAUTHENTICATED service={} rpc={}", serviceName, rpcMethod);
            }
            return;
        }

        switch (verified) {
            case ServicePrincipal sp ->
                    log.debug("reason=SERVICE_PRINCIPAL principalKind=SERVICE service={} rpc={} callerService={}",
                            serviceName, rpcMethod, sp.serviceName());
            case UserPrincipal up -> compareUser("JWT_USER", up.internalUserId(), up.keycloakSub(),
                    rpcMethod, suppliedUserId, suppliedPresent);
            case AssertedUserPrincipal aup -> compareUser("ASSERTED_USER", aup.internalUserId(), aup.keycloakSub(),
                    rpcMethod, suppliedUserId, suppliedPresent);
            // Staff have no org-service internal_user_id to compare against x-user-id at all — a
            // different identity universe entirely (see StaffPrincipal's own doc) — so this is just a
            // presence log, not a match/mismatch comparison like the two branches above.
            case StaffPrincipal sp ->
                    log.debug("reason=STAFF_PRINCIPAL principalKind=STAFF service={} rpc={} sub={} role={}",
                            serviceName, rpcMethod, sp.keycloakSub(), sp.role());
        }
    }

    private void compareUser(String principalKind, String internalUserId, String keycloakSub, String rpcMethod,
            String suppliedUserId, boolean suppliedPresent) {
        boolean hasInternalUserId = internalUserId != null && !internalUserId.isBlank();

        if (!hasInternalUserId) {
            log.warn("reason=INTERNAL_USER_ID_UNRESOLVED principalKind={} service={} rpc={} sub={} supplied={}",
                    principalKind, serviceName, rpcMethod, keycloakSub, suppliedUserId);
            return;
        }

        if (!suppliedPresent) {
            // DEBUG, not WARN: service-to-service calls never carry x-user-id (by design — they forward the
            // verified JWT instead), so this fired on every internal hop. In the 2026-10-20 load test it was
            // ~1,000 lines/s from org-service at 80 searches/s, and shipping them cost ~1.5 cores. The
            // signals that mean something stay at WARN: MISMATCH, NO_VERIFIABLE_IDENTITY, UNRESOLVED.
            log.debug("reason=VERIFIED_NOT_PROPAGATED principalKind={} service={} rpc={} verified={}",
                    principalKind, serviceName, rpcMethod, internalUserId);
            return;
        }

        if (!internalUserId.equals(suppliedUserId)) {
            log.warn("reason=MISMATCH principalKind={} service={} rpc={} verified={} supplied={}",
                    principalKind, serviceName, rpcMethod, internalUserId, suppliedUserId);
            return;
        }

        log.debug("reason=MATCH principalKind={} service={} rpc={} userId={}",
                principalKind, serviceName, rpcMethod, internalUserId);
    }
}

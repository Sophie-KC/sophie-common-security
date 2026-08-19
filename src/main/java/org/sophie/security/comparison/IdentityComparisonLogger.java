package org.sophie.security.comparison;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sophie.security.principal.AssertedUserPrincipal;
import org.sophie.security.principal.ServicePrincipal;
import org.sophie.security.principal.SophiePrincipal;
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
            log.warn("reason=VERIFIED_NOT_PROPAGATED principalKind={} service={} rpc={} verified={}",
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

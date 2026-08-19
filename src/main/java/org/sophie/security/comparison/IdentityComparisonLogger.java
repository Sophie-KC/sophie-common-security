package org.sophie.security.comparison;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sophie.security.principal.ServicePrincipal;
import org.sophie.security.principal.SophiePrincipal;
import org.sophie.security.principal.UserPrincipal;

/**
 * Logs identity-propagation signal for every call — the deliverable of phase 1. This measures whether
 * verified identity matches what the caller supplied via {@code x-user-id}, NOT authorization
 * correctness: a call that's already correctly scoped via a differently-named field (e.g.
 * {@code HasScopeAccessRequest.user_id}) still logs as "not propagated" here, which is accurate and is
 * exactly the phase-2 work list this exists to produce, not a false positive.
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

        if (verified instanceof ServicePrincipal sp) {
            log.debug("reason=SERVICE_PRINCIPAL service={} rpc={} callerService={}", serviceName, rpcMethod, sp.serviceName());
            return;
        }

        UserPrincipal up = (UserPrincipal) verified;
        if (!up.hasInternalUserId()) {
            log.warn("reason=INTERNAL_USER_ID_UNRESOLVED service={} rpc={} sub={} supplied={}",
                    serviceName, rpcMethod, up.keycloakSub(), suppliedUserId);
            return;
        }

        if (!suppliedPresent) {
            log.warn("reason=VERIFIED_NOT_PROPAGATED service={} rpc={} verified={}", serviceName, rpcMethod, up.internalUserId());
            return;
        }

        if (!up.internalUserId().equals(suppliedUserId)) {
            log.warn("reason=MISMATCH service={} rpc={} verified={} supplied={}",
                    serviceName, rpcMethod, up.internalUserId(), suppliedUserId);
            return;
        }

        log.debug("reason=MATCH service={} rpc={} userId={}", serviceName, rpcMethod, up.internalUserId());
    }
}

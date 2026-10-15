package org.sophie.security.autoconfigure;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "sophie.security")
public class SophieSecurityProperties {

    /** This service's own name, asserted as the caller identity on outbound internal-secret calls. */
    private String serviceName;

    /** When true, {@link org.sophie.security.grpc.JwtServerInterceptor} rejects unauthenticated
     *  calls, calls below an RPC's required {@link org.sophie.security.policy.PrincipalTier}, and
     *  calls whose supplied {@code x-user-id} contradicts the verified identity (forged-header
     *  impersonation) instead of just logging the comparison. Defaults to true (fail-closed): the
     *  phase-1 rollout is complete and every service already sets this explicitly, so the safe
     *  default is to enforce. Disabling it is an explicit, loud opt-out, never an accidental one. */
    private boolean enforce = true;

    private Internal internal = new Internal();

    @Data
    public static class Internal {
        /** Shared secret every service presents on calls with no end-user behind them. Distributed
         *  identically to all services via the on-prem install script / deployment secrets. */
        private String sharedSecret;
    }
}

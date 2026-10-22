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

    private RequireInternalUserId requireInternalUserId = new RequireInternalUserId();

    @Data
    public static class Internal {
        /** Shared secret every service presents on calls with no end-user behind them. Distributed
         *  identically to all services via the on-prem install script / deployment secrets. */
        private String sharedSecret;
    }

    /** {@link org.sophie.security.grpc.InternalUserIdRequiredServerInterceptor}: off unless a service
     *  turns it on. */
    @Data
    public static class RequireInternalUserId {
        private boolean enabled = false;
        /** Full gRPC method names (e.g. {@code com.platform.org.v1.OrgService/ValidateSession}) that
         *  legitimately serve a user whose account has no internal id yet. */
        private java.util.Set<String> exemptMethods = new java.util.HashSet<>();
    }
}

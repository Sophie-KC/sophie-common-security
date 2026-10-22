package org.sophie.security.grpc;

import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.Status;
import java.util.Set;
import org.sophie.security.context.SophieSecurityContext;
import org.sophie.security.principal.AssertedUserPrincipal;
import org.sophie.security.principal.SophiePrincipal;
import org.sophie.security.principal.UserPrincipal;

/**
 * Turns away a user call whose verified token carries no {@code internal_user_id} — an account whose
 * Keycloak attribute was never stamped — before a handler runs, instead of each handler doing
 * {@code UUID.fromString(currentInternalUserId())} and failing with a NullPointerException (a 500, and a
 * stackless log line per call). Answers PERMISSION_DENIED (403), not UNAUTHENTICATED: a 401 sends the web
 * client back through sign-in, and a new token would carry the same gap until org-service's reconciler
 * stamps the account — enough 401s in a minute open the client's re-auth breaker ("Sign-in isn't
 * working").
 *
 * <p>Opt-in per service ({@code sophie.security.require-internal-user-id.enabled}), registered right after
 * {@link JwtServerInterceptor}, whose verified principal it reads from the gRPC context. A service with
 * RPCs that legitimately serve a not-yet-provisioned user (org-service: session validation, federated
 * sign-up, invite-link joins) leaves it off or lists those methods in {@code exempt-methods}. Service and
 * staff principals are never affected.
 */
public class InternalUserIdRequiredServerInterceptor implements ServerInterceptor {

    private final Set<String> exemptMethods;

    public InternalUserIdRequiredServerInterceptor(Set<String> exemptMethods) {
        this.exemptMethods = exemptMethods == null ? Set.of() : Set.copyOf(exemptMethods);
    }

    @Override
    public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(
            ServerCall<ReqT, RespT> call, Metadata headers, ServerCallHandler<ReqT, RespT> next) {
        String methodName = call.getMethodDescriptor().getFullMethodName();
        if (lacksInternalUserId(SophieSecurityContext.PRINCIPAL.get()) && !exemptMethods.contains(methodName)) {
            call.close(Status.PERMISSION_DENIED.withDescription(
                    "Account setup isn't finished (no internal user id) for " + methodName), new Metadata());
            return new ServerCall.Listener<>() {};
        }
        return next.startCall(call, headers);
    }

    static boolean lacksInternalUserId(SophiePrincipal principal) {
        return switch (principal) {
            case UserPrincipal up -> !up.hasInternalUserId();
            case AssertedUserPrincipal aup -> aup.internalUserId() == null || aup.internalUserId().isBlank();
            case null, default -> false;
        };
    }
}

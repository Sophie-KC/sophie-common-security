package org.sophie.security.context;

import io.grpc.Context;
import org.sophie.security.principal.AssertedUserPrincipal;
import org.sophie.security.principal.SophiePrincipal;
import org.sophie.security.principal.UserPrincipal;

/**
 * Static {@link Context.Key}-backed accessor for the current call's verified principal — mirrors the
 * platform's existing convention (e.g. chat-service's {@code CurrentUserContext}) rather than a
 * {@code @RequestScope} bean, since gRPC calls never go through {@code DispatcherServlet} and a
 * request-scoped bean would not propagate correctly here. This is the source of truth; see
 * {@link PrincipalAccessor} for an injectable, mockable wrapper over the same values.
 */
public final class SophieSecurityContext {

    public static final Context.Key<SophiePrincipal> PRINCIPAL = Context.key("sophie-principal");
    public static final Context.Key<String> RAW_TOKEN = Context.key("sophie-raw-token");
    public static final Context.Key<String> FORWARDED_USER_ID = Context.key("sophie-forwarded-user-id");
    public static final Context.Key<String> FORWARDED_ORG_ROLE = Context.key("sophie-forwarded-org-role");

    /** Set by a service that resolved a real user's identity through an out-of-band mechanism it
     *  trusts (e.g. a redeemed ticket), not a JWT it can forward — see {@link
     *  org.sophie.security.principal.AssertedUserPrincipal}. */
    public static final Context.Key<String> ASSERTED_INTERNAL_USER_ID = Context.key("sophie-asserted-internal-user-id");
    public static final Context.Key<String> ASSERTED_KEYCLOAK_SUB = Context.key("sophie-asserted-keycloak-sub");

    private SophieSecurityContext() {}

    public static SophiePrincipal current() {
        return PRINCIPAL.get();
    }

    public static boolean isPresent() {
        return current() != null;
    }

    /** Static equivalent of {@link PrincipalAccessor#currentInternalUserId()}, for call sites that
     *  don't inject the accessor bean. */
    public static String currentInternalUserId() {
        SophiePrincipal principal = current();
        if (principal instanceof UserPrincipal up) {
            return up.internalUserId();
        }
        if (principal instanceof AssertedUserPrincipal aup) {
            return aup.internalUserId();
        }
        return null;
    }

    /**
     * A {@link Context} with the given out-of-band-resolved user identity attached, ready for {@code
     * .attach()} around outbound gRPC calls made from a thread with no inbound gRPC {@link Context} of
     * its own (e.g. a WebSocket handler). {@link org.sophie.security.grpc.IdentityForwardingClientInterceptor}
     * picks this up and asserts it downstream alongside this service's own shared-secret identity —
     * see its Javadoc for the full forwarding priority.
     */
    public static Context withAssertedUser(String internalUserId, String keycloakSub) {
        Context ctx = Context.current().withValue(ASSERTED_INTERNAL_USER_ID, internalUserId);
        if (keycloakSub != null) {
            ctx = ctx.withValue(ASSERTED_KEYCLOAK_SUB, keycloakSub);
        }
        return ctx;
    }
}

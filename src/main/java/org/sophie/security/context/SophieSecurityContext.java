package org.sophie.security.context;

import io.grpc.Context;
import org.sophie.security.principal.SophiePrincipal;

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

    private SophieSecurityContext() {}

    public static SophiePrincipal current() {
        return PRINCIPAL.get();
    }

    public static boolean isPresent() {
        return current() != null;
    }
}

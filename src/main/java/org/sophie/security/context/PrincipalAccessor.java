package org.sophie.security.context;

import org.sophie.security.principal.AssertedUserPrincipal;
import org.sophie.security.principal.SophiePrincipal;
import org.sophie.security.principal.UserPrincipal;

/** Injectable, mockable seam over {@link SophieSecurityContext}'s static accessor — not an alternative
 *  propagation mechanism, just a DI-friendly wrapper around it for consumers who want one. */
public interface PrincipalAccessor {

    SophiePrincipal current();

    default boolean isPresent() {
        return current() != null;
    }

    /**
     * The verified caller's internal user id, from whichever principal tier is present —
     * {@link UserPrincipal} (JWT-verified) or {@link AssertedUserPrincipal} (internal-service-vouched).
     * Null for a {@link org.sophie.security.principal.ServicePrincipal}, no principal at all, or a
     * {@link UserPrincipal} whose token predates user provisioning (see {@link UserPrincipal#hasInternalUserId()}).
     *
     * <p>This is the phase-2 replacement for reading a client-supplied {@code requested_by}-style
     * request field: read the verified identity from here instead, never from the request.
     */
    default String currentInternalUserId() {
        SophiePrincipal principal = current();
        if (principal instanceof UserPrincipal up) {
            return up.internalUserId();
        }
        if (principal instanceof AssertedUserPrincipal aup) {
            return aup.internalUserId();
        }
        return null;
    }
}

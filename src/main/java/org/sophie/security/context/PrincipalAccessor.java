package org.sophie.security.context;

import org.sophie.security.principal.SophiePrincipal;

/** Injectable, mockable seam over {@link SophieSecurityContext}'s static accessor — not an alternative
 *  propagation mechanism, just a DI-friendly wrapper around it for consumers who want one. */
public interface PrincipalAccessor {

    SophiePrincipal current();

    default boolean isPresent() {
        return current() != null;
    }
}

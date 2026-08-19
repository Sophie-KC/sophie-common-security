package org.sophie.security.context;

import org.sophie.security.principal.SophiePrincipal;

public class DefaultPrincipalAccessor implements PrincipalAccessor {

    @Override
    public SophiePrincipal current() {
        return SophieSecurityContext.current();
    }
}

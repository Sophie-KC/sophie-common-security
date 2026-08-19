package org.sophie.security.principal;

/** A background/internal caller authenticated via the shared internal-service secret — never a user. */
public record ServicePrincipal(String serviceName) implements SophiePrincipal {}

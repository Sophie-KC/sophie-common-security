package org.sophie.security.principal;

/** Who a gRPC caller cryptographically proved themselves to be. */
public sealed interface SophiePrincipal permits UserPrincipal, ServicePrincipal {}

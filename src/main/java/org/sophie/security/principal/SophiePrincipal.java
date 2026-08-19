package org.sophie.security.principal;

/** Who a gRPC caller proved themselves to be — see {@link UserPrincipal} and {@link AssertedUserPrincipal}
 *  for two meaningfully different strengths of "proved." */
public sealed interface SophiePrincipal permits UserPrincipal, ServicePrincipal, AssertedUserPrincipal {}

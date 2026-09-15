package org.sophie.security.principal;

/** Who a gRPC caller proved themselves to be — see {@link UserPrincipal} and {@link AssertedUserPrincipal}
 *  for two meaningfully different strengths of "proved," and {@link StaffPrincipal} for a verified
 *  identity from an entirely separate (staff, not customer) trust domain. */
public sealed interface SophiePrincipal permits UserPrincipal, ServicePrincipal, AssertedUserPrincipal, StaffPrincipal {}

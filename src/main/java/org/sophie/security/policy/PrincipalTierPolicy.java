package org.sophie.security.policy;

/**
 * A service's explicit allowlist of which {@link PrincipalTier} each of its own RPCs requires,
 * once {@code sophie.security.enforce=true}. Register one {@code @Bean} per service listing only
 * the exceptions — anything not covered here requires {@link #DEFAULT_TIER}, matching the phase-2
 * rule that a privileged or tenant-crossing RPC must never quietly downgrade to accepting an
 * assertion. See {@code sophie-common-security/PRINCIPAL_TIERS.md} for the source-of-truth table
 * this should never diverge from.
 */
@FunctionalInterface
public interface PrincipalTierPolicy {

    /** Every RPC requires a genuine {@link org.sophie.security.principal.UserPrincipal} unless a
     *  policy bean explicitly says otherwise. */
    PrincipalTier DEFAULT_TIER = PrincipalTier.USER;

    /**
     * @param fullMethodName as returned by {@code ServerCall.getMethodDescriptor().getFullMethodName()},
     *     e.g. {@code "com.platform.org.v1.OrgService/IsOrgMember"}
     * @return the minimum tier this RPC accepts, or {@code null} to fall back to {@link #DEFAULT_TIER}
     */
    PrincipalTier requiredTier(String fullMethodName);
}

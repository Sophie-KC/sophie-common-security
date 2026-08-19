package org.sophie.security.policy;

import org.sophie.security.principal.AssertedUserPrincipal;
import org.sophie.security.principal.ServicePrincipal;
import org.sophie.security.principal.SophiePrincipal;
import org.sophie.security.principal.UserPrincipal;

/**
 * Strength ordering over {@link SophiePrincipal}, weakest first. Declared in enum order so
 * {@code ordinal()} comparison ({@code actual.ordinal() >= required.ordinal()}) is "meets or
 * exceeds the required tier."
 */
public enum PrincipalTier {
    /** Internal shared secret, no user behind the call. */
    SERVICE,
    /** Internal shared secret + a service-asserted user id. Proves "an internal caller vouches
     *  for this user," not the user's own signature — see {@link AssertedUserPrincipal}. */
    ASSERTED_USER,
    /** JWT-signature-verified real user. Strongest. */
    USER;

    /** Null if {@code principal} is null (no verifiable identity at all). */
    public static PrincipalTier of(SophiePrincipal principal) {
        if (principal instanceof UserPrincipal) {
            return USER;
        }
        if (principal instanceof AssertedUserPrincipal) {
            return ASSERTED_USER;
        }
        if (principal instanceof ServicePrincipal) {
            return SERVICE;
        }
        return null;
    }
}

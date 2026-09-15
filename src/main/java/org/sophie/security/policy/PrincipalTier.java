package org.sophie.security.policy;

import org.sophie.security.principal.AssertedUserPrincipal;
import org.sophie.security.principal.ServicePrincipal;
import org.sophie.security.principal.SophiePrincipal;
import org.sophie.security.principal.StaffPrincipal;
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
        // A verified staff identity is at least as strong as a verified customer one — same
        // signature-verified guarantee, just a different trust domain (see StaffPrincipal's own
        // doc). Role-specific authorization (is this PLATFORM_ADMIN, not just staff) is the
        // handler's job, never this tier check's.
        if (principal instanceof StaffPrincipal) {
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

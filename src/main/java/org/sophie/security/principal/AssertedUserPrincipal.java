package org.sophie.security.principal;

/**
 * A user identity vouched for by a trusted internal service, rather than independently verified via a
 * Keycloak-signed JWT — e.g. websocket-service, whose own callers authenticate via a short-lived
 * ticket (not a JWT it can forward), asserting the identity it resolved from that ticket on its own
 * outbound calls. The internal shared secret proves {@code assertingService} is a genuine internal
 * caller; it does NOT cryptographically prove {@code keycloakSub}/{@code internalUserId} the way a
 * verified JWT signature does — any service holding the secret could assert any user id. Kept as a
 * distinct type from {@link UserPrincipal}, not a shared shape, specifically so this weaker guarantee
 * can never be silently treated as equivalent to a JWT-verified one in downstream authorization logic.
 */
public record AssertedUserPrincipal(String assertingService, String keycloakSub, String internalUserId)
        implements SophiePrincipal {

    public boolean hasInternalUserId() {
        return internalUserId != null && !internalUserId.isBlank();
    }
}

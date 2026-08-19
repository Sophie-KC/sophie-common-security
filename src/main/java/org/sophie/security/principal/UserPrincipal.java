package org.sophie.security.principal;

/**
 * A verified Keycloak-issued caller. {@code internalUserId} is org-service's own {@code users.id} —
 * distinct from {@code keycloakSub} and never to be conflated with it — sourced from the token's
 * {@code internal_user_id} claim, null when that claim is absent (e.g. a token minted before user
 * provisioning completed). Treat a null {@code internalUserId} as unresolved identity, never as a
 * license to fall back to a client-supplied value.
 */
public record UserPrincipal(String keycloakSub, String internalUserId, String rawToken) implements SophiePrincipal {

    public boolean hasInternalUserId() {
        return internalUserId != null && !internalUserId.isBlank();
    }
}

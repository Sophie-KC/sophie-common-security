package org.sophie.security.principal;

/**
 * A platform staff member — JWT-signature-verified, same as {@link UserPrincipal}, but against the
 * isolated {@code sophie-staff} Keycloak realm, never the customer {@code sophie} realm. Staff have no
 * row in any org-service {@code users}/{@code organizations} table (they aren't a customer, aren't a
 * member of any org, and {@code keycloakSub} is only ever looked up against org-service's own
 * {@code platform_staff} table, never against customer identity) — kept as a distinct type from
 * {@link UserPrincipal} specifically so the two identity universes can never be conflated in
 * downstream authorization logic. {@code role} is whichever of {@code PLATFORM_ADMIN}/
 * {@code BILLING_STAFF}/{@code SUPPORT} the staff realm's {@code realm_access.roles} claim carried —
 * the token's own claim, never a client-supplied value, but still re-checked against the caller's
 * live {@code platform_staff} row before any privileged action (a role captured at token-mint time
 * could be stale if revoked since).
 */
public record StaffPrincipal(String keycloakSub, String role, String rawToken) implements SophiePrincipal {}

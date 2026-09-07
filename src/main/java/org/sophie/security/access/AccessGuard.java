package org.sophie.security.access;

import io.grpc.Status;
import java.util.UUID;
import net.devh.boot.grpc.client.inject.GrpcClient;
import org.sophie.orgservice.grpc.MembershipStatus;
import org.sophie.orgservice.grpc.OrgServiceGrpc;
import org.sophie.orgservice.grpc.ValidateSessionRequest;
import org.sophie.orgservice.grpc.ValidateSessionResponse;
import org.sophie.security.context.SophieSecurityContext;

/**
 * Single shared authorization checkpoint for every service that owns org-scoped data. A handler that
 * accepts a client-supplied resource id must call one of these methods, passing the resource's OWN
 * org id — resolved from that service's own database, never trusted from a field the client sent
 * alongside the resource id — as its first statement, before touching data.
 *
 * <p>Backed by Org Service's {@code ValidateSession(keycloak_sub, org_id)} RPC — one round trip
 * returns membership status, role ids, the full permission set, and admin status together, rather
 * than the three separate RPCs (`IsOrgMember`/`IsOrgAdmin`/`HasPermission`) this class used before.
 * Calls it on every invocation, no caching: an unmeasured cache with no invalidation story is worse
 * than a per-request RPC (see the auth remediation plan's Step 4 note). If this ever needs a cache,
 * it needs event-driven invalidation on role/permission/membership change first, not a TTL alone.
 *
 * <p>Throws {@link io.grpc.StatusRuntimeException} directly ({@code PERMISSION_DENIED} /
 * {@code UNAUTHENTICATED}) rather than a library-specific exception type, so it needs no per-service
 * mapping: every service's existing {@code GrpcErrors}-style handler already passes a
 * {@code StatusRuntimeException} through unchanged, and api-gateway's {@code GrpcExceptionHandler}
 * already maps those codes to 403/401.
 */
public class AccessGuard {

    private final OrgServiceGrpc.OrgServiceBlockingStub orgServiceStub;

    public AccessGuard(@GrpcClient("org-service") OrgServiceGrpc.OrgServiceBlockingStub orgServiceStub) {
        this.orgServiceStub = orgServiceStub;
    }

    /**
     * Caller must be an ACTIVE member (any role) of {@code orgId}.
     *
     * @return the caller's own user id, for convenience at call sites that need it right after.
     */
    public UUID requireOrgMember(UUID orgId) {
        ValidateSessionResponse session = validate(orgId);
        if (session.getMembershipStatus() != MembershipStatus.ACTIVE) {
            throw Status.PERMISSION_DENIED
                    .withDescription("Caller is not a member of org " + orgId)
                    .asRuntimeException();
        }
        return callerId(session);
    }

    /** Caller must hold the ORG-scope "Org Admin" role on {@code orgId}. */
    public UUID requireOrgAdmin(UUID orgId) {
        ValidateSessionResponse session = validate(orgId);
        if (!session.getIsOrgAdmin()) {
            throw Status.PERMISSION_DENIED
                    .withDescription("Caller is not an admin of org " + orgId)
                    .asRuntimeException();
        }
        return callerId(session);
    }

    /** Caller must hold {@code permissionCode} at ORG scope on {@code orgId} (directly, or implicitly
     *  as Org Admin — {@code ValidateSession} already expands admin to the full permission catalog). */
    public UUID requireOrgPermission(UUID orgId, String permissionCode) {
        ValidateSessionResponse session = validate(orgId);
        if (!session.getPermissionsList().contains(permissionCode)) {
            throw Status.PERMISSION_DENIED
                    .withDescription("Caller lacks permission '" + permissionCode + "' on org " + orgId)
                    .asRuntimeException();
        }
        return callerId(session);
    }

    private ValidateSessionResponse validate(UUID orgId) {
        String keycloakSub = SophieSecurityContext.currentKeycloakSub();
        if (keycloakSub == null) {
            throw Status.UNAUTHENTICATED
                    .withDescription("No authenticated user in call context")
                    .asRuntimeException();
        }
        ValidateSessionResponse session = orgServiceStub.validateSession(ValidateSessionRequest.newBuilder()
                .setKeycloakSub(keycloakSub)
                .setOrgId(orgId.toString())
                .build());
        if (!session.getValid()) {
            throw Status.UNAUTHENTICATED
                    .withDescription("No Org Service user record for this identity")
                    .asRuntimeException();
        }
        return session;
    }

    private static UUID callerId(ValidateSessionResponse session) {
        return UUID.fromString(session.getUserId());
    }
}

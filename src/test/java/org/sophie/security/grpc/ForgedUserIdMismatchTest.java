package org.sophie.security.grpc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.Status;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.sophie.security.comparison.IdentityComparisonLogger;
import org.sophie.security.jwt.JwtVerifier;
import org.sophie.security.policy.PrincipalTier;
import org.sophie.security.policy.PrincipalTierPolicy;
import org.sophie.security.principal.AssertedUserPrincipal;
import org.sophie.security.principal.ServicePrincipal;
import org.sophie.security.principal.StaffPrincipal;
import org.sophie.security.principal.UserPrincipal;

/**
 * Locks in the forged-header impersonation guard: a supplied {@code x-user-id} that contradicts the
 * verified identity is the one signal that always means an attempt to act as another user, so under
 * {@code enforce} the call must be rejected before the handler runs. Covers both the pure decision
 * ({@link IdentityComparisonLogger#isForgedUserIdMismatch}) and the interceptor wiring.
 */
class ForgedUserIdMismatchTest {

    private static final String SHARED_SECRET = "test-shared-secret";
    private static final Metadata.Key<String> INTERNAL_SECRET =
            Metadata.Key.of("x-internal-service-secret", Metadata.ASCII_STRING_MARSHALLER);
    private static final Metadata.Key<String> INTERNAL_SERVICE_NAME =
            Metadata.Key.of("x-internal-service-name", Metadata.ASCII_STRING_MARSHALLER);
    private static final Metadata.Key<String> ASSERTED_USER_ID =
            Metadata.Key.of("x-asserted-internal-user-id", Metadata.ASCII_STRING_MARSHALLER);
    private static final Metadata.Key<String> USER_ID =
            Metadata.Key.of("x-user-id", Metadata.ASCII_STRING_MARSHALLER);

    private static final MethodDescriptor<Object, Object> METHOD = MethodDescriptor.<Object, Object>newBuilder()
            .setType(MethodDescriptor.MethodType.UNARY)
            .setFullMethodName("test.Service/Method")
            .setRequestMarshaller(noopMarshaller())
            .setResponseMarshaller(noopMarshaller())
            .build();

    // Permissive tier so these tests isolate the x-user-id mismatch control rather than the tier gate
    // (an AssertedUserPrincipal is below the USER DEFAULT_TIER and would otherwise be rejected first).
    private static final PrincipalTierPolicy ACCEPT_ASSERTED = method -> PrincipalTier.ASSERTED_USER;

    // ---- Pure decision ----

    @Test
    void mismatchedUserPrincipalIsForged() {
        assertTrue(IdentityComparisonLogger.isForgedUserIdMismatch(
                new UserPrincipal("sub", "internal-user-1", "token"), "internal-user-2"));
    }

    @Test
    void matchingUserPrincipalIsNotForged() {
        assertFalse(IdentityComparisonLogger.isForgedUserIdMismatch(
                new UserPrincipal("sub", "internal-user-1", "token"), "internal-user-1"));
    }

    @Test
    void absentSuppliedIdIsNeverForged() {
        // Many correctly-scoped calls legitimately carry no x-user-id (scoped via a named request field).
        assertFalse(IdentityComparisonLogger.isForgedUserIdMismatch(
                new UserPrincipal("sub", "internal-user-1", "token"), null));
        assertFalse(IdentityComparisonLogger.isForgedUserIdMismatch(
                new UserPrincipal("sub", "internal-user-1", "token"), "  "));
    }

    @Test
    void mismatchedAssertedUserPrincipalIsForged() {
        assertTrue(IdentityComparisonLogger.isForgedUserIdMismatch(
                new AssertedUserPrincipal("websocket-service", "sub", "internal-user-1"), "internal-user-9"));
    }

    @Test
    void serviceStaffNullAndUnresolvedAreNeverForged() {
        assertFalse(IdentityComparisonLogger.isForgedUserIdMismatch(new ServicePrincipal("drive-service"), "anything"));
        assertFalse(IdentityComparisonLogger.isForgedUserIdMismatch(new StaffPrincipal("sub", "PLATFORM_ADMIN", "tok"), "anything"));
        assertFalse(IdentityComparisonLogger.isForgedUserIdMismatch(null, "anything"));
        // Unresolved internal id on the principal: nothing to contradict, so not a forgery signal here.
        assertFalse(IdentityComparisonLogger.isForgedUserIdMismatch(new UserPrincipal("sub", null, "token"), "internal-user-2"));
    }

    // ---- Interceptor wiring (enforce on) ----

    @Test
    void enforcingInterceptorRejectsForgedUserIdWithPermissionDenied() {
        // Asserted-user envelope (no JWT needed): verified internal id is user-1, but x-user-id claims user-2.
        Metadata headers = new Metadata();
        headers.put(INTERNAL_SECRET, SHARED_SECRET);
        headers.put(INTERNAL_SERVICE_NAME, "websocket-service");
        headers.put(ASSERTED_USER_ID, "internal-user-1");
        headers.put(USER_ID, "internal-user-2");

        AtomicReference<Status> closed = new AtomicReference<>();
        AtomicBoolean handlerRan = new AtomicBoolean(false);
        JwtServerInterceptor interceptor = new JwtServerInterceptor(
                unusableJwtVerifier(), SHARED_SECRET, new IdentityComparisonLogger("doc-service"), true, ACCEPT_ASSERTED);

        ServerCallHandler<Object, Object> handler = (call, md) -> {
            handlerRan.set(true);
            return new ServerCall.Listener<>() {};
        };
        interceptor.interceptCall(new CapturingServerCall(closed), headers, handler);

        assertFalse(handlerRan.get(), "handler must not run for a forged x-user-id");
        assertEquals(Status.Code.PERMISSION_DENIED, closed.get().getCode());
    }

    @Test
    void enforcingInterceptorAllowsMatchingUserId() {
        Metadata headers = new Metadata();
        headers.put(INTERNAL_SECRET, SHARED_SECRET);
        headers.put(INTERNAL_SERVICE_NAME, "websocket-service");
        headers.put(ASSERTED_USER_ID, "internal-user-1");
        headers.put(USER_ID, "internal-user-1");

        AtomicReference<Status> closed = new AtomicReference<>();
        AtomicBoolean handlerRan = new AtomicBoolean(false);
        JwtServerInterceptor interceptor = new JwtServerInterceptor(
                unusableJwtVerifier(), SHARED_SECRET, new IdentityComparisonLogger("doc-service"), true, ACCEPT_ASSERTED);

        ServerCallHandler<Object, Object> handler = (call, md) -> {
            handlerRan.set(true);
            return new ServerCall.Listener<>() {};
        };
        interceptor.interceptCall(new CapturingServerCall(closed), headers, handler);

        assertTrue(handlerRan.get(), "handler must run when x-user-id matches the verified identity");
        assertNull(closed.get());
    }

    private static JwtVerifier unusableJwtVerifier() {
        return new JwtVerifier(
                "http://localhost:1/should-never-be-called/certs", "http://localhost:1/should-never-be-called");
    }

    private static MethodDescriptor.Marshaller<Object> noopMarshaller() {
        return new MethodDescriptor.Marshaller<>() {
            @Override
            public InputStream stream(Object value) {
                return new ByteArrayInputStream(new byte[0]);
            }

            @Override
            public Object parse(InputStream stream) {
                return new Object();
            }
        };
    }

    private static final class CapturingServerCall extends ServerCall<Object, Object> {
        private final AtomicReference<Status> closed;

        private CapturingServerCall(AtomicReference<Status> closed) {
            this.closed = closed;
        }

        @Override
        public void request(int numMessages) {}

        @Override
        public void sendHeaders(Metadata headers) {}

        @Override
        public void sendMessage(Object message) {}

        @Override
        public void close(Status status, Metadata trailers) {
            closed.set(status);
        }

        @Override
        public boolean isCancelled() {
            return false;
        }

        @Override
        public MethodDescriptor<Object, Object> getMethodDescriptor() {
            return METHOD;
        }
    }
}

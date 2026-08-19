package org.sophie.security.grpc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.Context;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.Status;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.sophie.security.comparison.IdentityComparisonLogger;
import org.sophie.security.context.SophieSecurityContext;
import org.sophie.security.jwt.JwtVerifier;
import org.sophie.security.principal.AssertedUserPrincipal;
import org.sophie.security.principal.ServicePrincipal;
import org.sophie.security.principal.SophiePrincipal;

/**
 * Verifies the exact mechanism websocket-service's WebSocket ticket auth depends on: a service with no
 * JWT to forward can still get a receiving service to resolve a real, named {@link
 * AssertedUserPrincipal} — not a bare {@link ServicePrincipal} — by attaching {@link
 * SophieSecurityContext#withAssertedUser} before an outbound call. Exercises the client interceptor's
 * metadata production and the server interceptor's metadata consumption directly (no network
 * transport), since the two must agree on the wire format.
 */
class AssertedUserPrincipalPropagationTest {

    private static final String SHARED_SECRET = "test-shared-secret";
    private static final MethodDescriptor<Object, Object> METHOD = MethodDescriptor.<Object, Object>newBuilder()
            .setType(MethodDescriptor.MethodType.UNARY)
            .setFullMethodName("test.Service/Method")
            .setRequestMarshaller(noopMarshaller())
            .setResponseMarshaller(noopMarshaller())
            .build();

    @Test
    void clientAttachedAssertedIdentityBecomesServerAssertedUserPrincipal() {
        // ---- Client side: attach an asserted identity, capture what the interceptor sends ----
        Context assertedContext = SophieSecurityContext.withAssertedUser("internal-user-42", "keycloak-sub-42");
        Context previous = assertedContext.attach();
        Metadata sentHeaders;
        try {
            sentHeaders = captureOutboundHeaders(new IdentityForwardingClientInterceptor("websocket-service", SHARED_SECRET));
        } finally {
            assertedContext.detach(previous);
        }

        // ---- Server side: feed those exact headers through JwtServerInterceptor ----
        SophiePrincipal resolved = resolvePrincipal(sentHeaders, SHARED_SECRET);

        AssertedUserPrincipal principal = assertInstanceOf(AssertedUserPrincipal.class, resolved);
        assertEquals("websocket-service", principal.assertingService());
        assertEquals("internal-user-42", principal.internalUserId());
        assertEquals("keycloak-sub-42", principal.keycloakSub());
        assertTrue(principal.hasInternalUserId());
    }

    @Test
    void noAssertedIdentityStillProducesPlainServicePrincipal() {
        // No Context attached at all — the existing, unchanged internal-secret-only path.
        Metadata sentHeaders = captureOutboundHeaders(new IdentityForwardingClientInterceptor("vcs-service", SHARED_SECRET));

        SophiePrincipal resolved = resolvePrincipal(sentHeaders, SHARED_SECRET);

        ServicePrincipal principal = assertInstanceOf(ServicePrincipal.class, resolved);
        assertEquals("vcs-service", principal.serviceName());
    }

    @Test
    void assertedIdentityIgnoredWithoutSharedSecretConfigured() {
        // A service with no shared secret configured must never send an asserted identity unaccompanied
        // — the assertion is only meaningful inside the secret-authenticated envelope.
        Context assertedContext = SophieSecurityContext.withAssertedUser("internal-user-42", "keycloak-sub-42");
        Context previous = assertedContext.attach();
        Metadata sentHeaders;
        try {
            sentHeaders = captureOutboundHeaders(new IdentityForwardingClientInterceptor("websocket-service", null));
        } finally {
            assertedContext.detach(previous);
        }

        assertNull(sentHeaders.get(Metadata.Key.of("x-asserted-internal-user-id", Metadata.ASCII_STRING_MARSHALLER)));
        assertNull(sentHeaders.get(Metadata.Key.of("x-internal-service-secret", Metadata.ASCII_STRING_MARSHALLER)));
    }

    @Test
    void wrongSharedSecretNeverProducesAssertedUserPrincipal() {
        Context assertedContext = SophieSecurityContext.withAssertedUser("internal-user-42", "keycloak-sub-42");
        Context previous = assertedContext.attach();
        Metadata sentHeaders;
        try {
            sentHeaders = captureOutboundHeaders(new IdentityForwardingClientInterceptor("websocket-service", SHARED_SECRET));
        } finally {
            assertedContext.detach(previous);
        }

        // Receiving service configured with a DIFFERENT secret — must never trust the assertion.
        SophiePrincipal resolved = resolvePrincipal(sentHeaders, "a-completely-different-secret");
        assertNull(resolved);
    }

    private static Metadata captureOutboundHeaders(IdentityForwardingClientInterceptor interceptor) {
        AtomicReference<Metadata> captured = new AtomicReference<>();
        Channel fakeChannel = new Channel() {
            @Override
            public <ReqT, RespT> io.grpc.ClientCall<ReqT, RespT> newCall(
                    MethodDescriptor<ReqT, RespT> methodDescriptor, CallOptions callOptions) {
                return new CapturingClientCall<>(captured);
            }

            @Override
            public String authority() {
                return "test";
            }
        };

        io.grpc.ClientCall<Object, Object> call = interceptor.interceptCall(METHOD, CallOptions.DEFAULT, fakeChannel);
        call.start(new io.grpc.ClientCall.Listener<>() {}, new Metadata());
        return captured.get();
    }

    private static SophiePrincipal resolvePrincipal(Metadata headers, String expectedSecret) {
        AtomicReference<SophiePrincipal> resolved = new AtomicReference<>();
        JwtServerInterceptor interceptor = new JwtServerInterceptor(
                unusableJwtVerifier(), expectedSecret, new IdentityComparisonLogger("doc-service"));

        ServerCallHandler<Object, Object> handler = (call, md) -> {
            resolved.set(SophieSecurityContext.current());
            return new ServerCall.Listener<>() {};
        };

        interceptor.interceptCall(new NoopServerCall(), headers, handler);
        return resolved.get();
    }

    /** Never actually invoked in these tests — no {@code authorization} header is ever set, so
     *  JwtServerInterceptor never reaches the JWT-verification branch. */
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

    private static final class CapturingClientCall<ReqT, RespT> extends io.grpc.ClientCall<ReqT, RespT> {
        private final AtomicReference<Metadata> captured;

        private CapturingClientCall(AtomicReference<Metadata> captured) {
            this.captured = captured;
        }

        @Override
        public void start(Listener<RespT> responseListener, Metadata headers) {
            captured.set(headers);
        }

        @Override
        public void request(int numMessages) {}

        @Override
        public void cancel(String message, Throwable cause) {}

        @Override
        public void halfClose() {}

        @Override
        public void sendMessage(ReqT message) {}
    }

    private static final class NoopServerCall extends ServerCall<Object, Object> {
        @Override
        public void request(int numMessages) {}

        @Override
        public void sendHeaders(Metadata headers) {}

        @Override
        public void sendMessage(Object message) {}

        @Override
        public void close(Status status, Metadata trailers) {}

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

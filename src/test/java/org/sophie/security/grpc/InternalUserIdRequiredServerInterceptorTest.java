package org.sophie.security.grpc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.grpc.Context;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.Status;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.sophie.security.context.SophieSecurityContext;
import org.sophie.security.principal.ServicePrincipal;
import org.sophie.security.principal.SophiePrincipal;
import org.sophie.security.principal.UserPrincipal;

/**
 * A user call with no internal_user_id is turned away (403) before the handler runs — where handlers used
 * to fail with a NullPointerException on {@code UUID.fromString(null)} — unless the method is exempt; a
 * provisioned user and a service principal pass untouched.
 */
class InternalUserIdRequiredServerInterceptorTest {

    private static final String METHOD_NAME = "com.platform.task.v1.TaskService/CreateTaskComment";

    @Test
    void aUserWithoutAnInternalIdIsTurnedAwayAsForbidden() {
        Outcome outcome = call(new UserPrincipal("sub", null, "token"), Set.of());

        assertFalse(outcome.handlerRan);
        assertEquals(Status.Code.PERMISSION_DENIED, outcome.closed.getCode());
    }

    @Test
    void aProvisionedUserAndAServiceGoThrough() {
        Outcome user = call(new UserPrincipal("sub", "6b1c0c7e-3f1e-4a52-9a43-2a4b7c1d9e10", "token"), Set.of());
        Outcome service = call(new ServicePrincipal("import-service"), Set.of());

        assertTrue(user.handlerRan);
        assertNull(user.closed);
        assertTrue(service.handlerRan);
        assertNull(service.closed);
    }

    @Test
    void anExemptMethodServesTheUnprovisionedUser() {
        Outcome outcome = call(new UserPrincipal("sub", null, "token"), Set.of(METHOD_NAME));

        assertTrue(outcome.handlerRan);
        assertNull(outcome.closed);
    }

    private record Outcome(boolean handlerRan, Status closed) {}

    private static Outcome call(SophiePrincipal principal, Set<String> exempt) {
        AtomicBoolean ran = new AtomicBoolean();
        AtomicReference<Status> closed = new AtomicReference<>();
        ServerCallHandler<Object, Object> handler = (c, md) -> {
            ran.set(true);
            return new ServerCall.Listener<>() {};
        };
        Context context = Context.current().withValue(SophieSecurityContext.PRINCIPAL, principal);
        Context previous = context.attach();
        try {
            new InternalUserIdRequiredServerInterceptor(exempt).interceptCall(new CapturingServerCall(closed), new Metadata(), handler);
        } finally {
            context.detach(previous);
        }
        return new Outcome(ran.get(), closed.get());
    }

    private static final MethodDescriptor<Object, Object> METHOD = MethodDescriptor.<Object, Object>newBuilder()
            .setType(MethodDescriptor.MethodType.UNARY)
            .setFullMethodName(METHOD_NAME)
            .setRequestMarshaller(noopMarshaller())
            .setResponseMarshaller(noopMarshaller())
            .build();

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

package org.sophie.security.grpc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.nimbusds.jwt.JWTClaimsSet;
import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.Status;
import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.sophie.security.comparison.IdentityComparisonLogger;
import org.sophie.security.context.SophieSecurityContext;
import org.sophie.security.jwt.JwtVerifier;
import org.sophie.security.principal.SophiePrincipal;
import org.sophie.security.principal.StaffPrincipal;
import org.sophie.security.principal.UserPrincipal;

/**
 * The staff-realm fallback added to {@link JwtServerInterceptor} for org-service's admin surface
 * (2026-09-15). A token is from exactly one realm, so the staff verifier is only ever consulted after
 * the customer-realm one rejects the token outright — never both accepting the same token.
 */
class StaffPrincipalResolutionTest {

    private static final MethodDescriptorHolder METHOD = new MethodDescriptorHolder();

    @Test
    void customerTokenResolvesAsUserPrincipalEvenWithAStaffVerifierConfigured() {
        JwtVerifier customerVerifier = claimsAlwaysVerifyTo(
                new JWTClaimsSet.Builder().subject("customer-sub-1").claim("internal_user_id", "user-1").build());
        JwtVerifier staffVerifier = alwaysRejects();

        SophiePrincipal resolved = resolve(customerVerifier, staffVerifier, bearerHeader("irrelevant-token"));

        UserPrincipal principal = assertInstanceOf(UserPrincipal.class, resolved);
        assertEquals("customer-sub-1", principal.keycloakSub());
        assertEquals("user-1", principal.internalUserId());
    }

    @Test
    void staffTokenResolvesAsStaffPrincipalOnlyWhenCustomerVerifierRejectsFirst() {
        JwtVerifier customerVerifier = alwaysRejects();
        JwtVerifier staffVerifier = claimsAlwaysVerifyTo(new JWTClaimsSet.Builder()
                .subject("staff-sub-1")
                .claim("realm_access", Map.of("roles", List.of("offline_access", "PLATFORM_ADMIN", "default-roles-sophie-staff")))
                .build());

        SophiePrincipal resolved = resolve(customerVerifier, staffVerifier, bearerHeader("irrelevant-token"));

        StaffPrincipal principal = assertInstanceOf(StaffPrincipal.class, resolved);
        assertEquals("staff-sub-1", principal.keycloakSub());
        assertEquals("PLATFORM_ADMIN", principal.role());
    }

    @Test
    void staffTokenIsRejectedOutrightWhenNoStaffVerifierIsConfigured() {
        // Every service except org-service today — the exact pre-existing single-verifier behavior,
        // unchanged: a token neither verifier (because there is no second one) accepts resolves to no
        // principal at all, not a silent StaffPrincipal.
        JwtVerifier customerVerifier = alwaysRejects();

        SophiePrincipal resolved = resolve(customerVerifier, null, bearerHeader("irrelevant-token"));

        assertNull(resolved);
    }

    @Test
    void aTokenWithNoRecognisedStaffRoleResolvesWithANullRole() {
        JwtVerifier customerVerifier = alwaysRejects();
        JwtVerifier staffVerifier = claimsAlwaysVerifyTo(new JWTClaimsSet.Builder()
                .subject("staff-sub-2")
                .claim("realm_access", Map.of("roles", List.of("offline_access", "default-roles-sophie-staff")))
                .build());

        SophiePrincipal resolved = resolve(customerVerifier, staffVerifier, bearerHeader("irrelevant-token"));

        StaffPrincipal principal = assertInstanceOf(StaffPrincipal.class, resolved);
        assertNull(principal.role());
    }

    private static Metadata bearerHeader(String token) {
        Metadata headers = new Metadata();
        headers.put(Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER), "Bearer " + token);
        return headers;
    }

    private static SophiePrincipal resolve(JwtVerifier customerVerifier, JwtVerifier staffVerifier, Metadata headers) {
        AtomicReference<SophiePrincipal> resolved = new AtomicReference<>();
        JwtServerInterceptor interceptor = new JwtServerInterceptor(
                customerVerifier, staffVerifier, null, new IdentityComparisonLogger("org-service"), false, null);

        ServerCallHandler<Object, Object> handler = (call, md) -> {
            resolved.set(SophieSecurityContext.current());
            return new ServerCall.Listener<>() {};
        };

        interceptor.interceptCall(METHOD.serverCall(), headers, handler);
        return resolved.get();
    }

    /** Never actually parses a real JWT — always throws, so the interceptor moves on to whichever
     *  fallback (or none) the test configured. */
    private static JwtVerifier alwaysRejects() {
        return new JwtVerifier("http://localhost:1/should-never-be-called/certs", "http://localhost:1/should-never-be-called") {
            @Override
            public JWTClaimsSet verify(String compactJwt) throws ParseException {
                throw new ParseException("test double: always rejects", 0);
            }
        };
    }

    private static JwtVerifier claimsAlwaysVerifyTo(JWTClaimsSet claims) {
        return new JwtVerifier("http://localhost:1/should-never-be-called/certs", "http://localhost:1/should-never-be-called") {
            @Override
            public JWTClaimsSet verify(String compactJwt) {
                return claims;
            }
        };
    }

    private static final class MethodDescriptorHolder {
        private final io.grpc.MethodDescriptor<Object, Object> descriptor = io.grpc.MethodDescriptor.<Object, Object>newBuilder()
                .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
                .setFullMethodName("test.Service/Method")
                .setRequestMarshaller(noopMarshaller())
                .setResponseMarshaller(noopMarshaller())
                .build();

        private ServerCall<Object, Object> serverCall() {
            return new ServerCall<>() {
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
                public io.grpc.MethodDescriptor<Object, Object> getMethodDescriptor() {
                    return descriptor;
                }
            };
        }

        private static io.grpc.MethodDescriptor.Marshaller<Object> noopMarshaller() {
            return new io.grpc.MethodDescriptor.Marshaller<>() {
                @Override
                public java.io.InputStream stream(Object value) {
                    return new java.io.ByteArrayInputStream(new byte[0]);
                }

                @Override
                public Object parse(java.io.InputStream stream) {
                    return new Object();
                }
            };
        }
    }
}

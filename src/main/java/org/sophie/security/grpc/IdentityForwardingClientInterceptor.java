package org.sophie.security.grpc;

import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.ClientCall;
import io.grpc.ClientInterceptor;
import io.grpc.ForwardingClientCall;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import org.sophie.security.context.SophieSecurityContext;

/**
 * Forwards identity on every outbound call, broadly — not hand-wired per call site — so no internal
 * hop can silently regress to sending nothing. Priority: the original raw JWT if this call thread has
 * one (so a downstream signature check still succeeds against the same JWKS) &gt; the inbound
 * {@code x-user-id}/{@code x-org-role} this service itself received &gt; this service's own shared
 * secret, asserting a {@code ServicePrincipal} for calls with no user context at all — background
 * jobs, queue consumers, or callers with no gRPC {@link io.grpc.Context} propagated to this thread
 * (e.g. websocket-service's WS-handshake-authenticated handlers).
 */
public class IdentityForwardingClientInterceptor implements ClientInterceptor {

    static final Metadata.Key<String> AUTHORIZATION =
            Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER);
    static final Metadata.Key<String> USER_ID =
            Metadata.Key.of("x-user-id", Metadata.ASCII_STRING_MARSHALLER);
    static final Metadata.Key<String> ORG_ROLE =
            Metadata.Key.of("x-org-role", Metadata.ASCII_STRING_MARSHALLER);
    static final Metadata.Key<String> INTERNAL_SECRET =
            Metadata.Key.of("x-internal-service-secret", Metadata.ASCII_STRING_MARSHALLER);
    static final Metadata.Key<String> INTERNAL_SERVICE_NAME =
            Metadata.Key.of("x-internal-service-name", Metadata.ASCII_STRING_MARSHALLER);

    private final String serviceName;
    private final String sharedSecret;

    public IdentityForwardingClientInterceptor(String serviceName, String sharedSecret) {
        this.serviceName = serviceName;
        this.sharedSecret = sharedSecret;
    }

    @Override
    public <ReqT, RespT> ClientCall<ReqT, RespT> interceptCall(
            MethodDescriptor<ReqT, RespT> method, CallOptions callOptions, Channel next) {
        return new ForwardingClientCall.SimpleForwardingClientCall<>(next.newCall(method, callOptions)) {
            @Override
            public void start(Listener<RespT> responseListener, Metadata headers) {
                String rawToken = SophieSecurityContext.RAW_TOKEN.get();
                String forwardedUserId = SophieSecurityContext.FORWARDED_USER_ID.get();
                String forwardedOrgRole = SophieSecurityContext.FORWARDED_ORG_ROLE.get();

                if (rawToken != null && !rawToken.isBlank()) {
                    headers.put(AUTHORIZATION, "Bearer " + rawToken);
                } else if (forwardedUserId != null && !forwardedUserId.isBlank()) {
                    headers.put(USER_ID, forwardedUserId);
                    if (forwardedOrgRole != null && !forwardedOrgRole.isBlank()) {
                        headers.put(ORG_ROLE, forwardedOrgRole);
                    }
                } else if (sharedSecret != null && !sharedSecret.isBlank()) {
                    headers.put(INTERNAL_SECRET, sharedSecret);
                    headers.put(INTERNAL_SERVICE_NAME, serviceName);
                }
                super.start(responseListener, headers);
            }
        };
    }
}

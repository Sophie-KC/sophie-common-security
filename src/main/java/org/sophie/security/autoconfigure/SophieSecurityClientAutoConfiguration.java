package org.sophie.security.autoconfigure;

import io.grpc.ClientInterceptor;
import net.devh.boot.grpc.client.interceptor.GrpcGlobalClientInterceptor;
import org.sophie.security.grpc.IdentityForwardingClientInterceptor;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.Bean;

/** Applies to every {@code @GrpcClient} stub in the service — see {@link IdentityForwardingClientInterceptor}
 *  for the forwarding priority. No-ops on services with no gRPC client at all (none exist on this
 *  platform today, but the guard costs nothing). */
@AutoConfiguration
@AutoConfigureAfter(SophieSecurityAutoConfiguration.class)
@ConditionalOnClass(name = "net.devh.boot.grpc.client.interceptor.GrpcGlobalClientInterceptor")
public class SophieSecurityClientAutoConfiguration {

    @Bean
    @GrpcGlobalClientInterceptor
    public ClientInterceptor sophieIdentityForwardingClientInterceptor(SophieSecurityProperties props) {
        return new IdentityForwardingClientInterceptor(props.getServiceName(), props.getInternal().getSharedSecret());
    }
}

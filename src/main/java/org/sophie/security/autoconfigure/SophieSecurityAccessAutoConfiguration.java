package org.sophie.security.autoconfigure;

import net.devh.boot.grpc.client.inject.GrpcClient;
import org.sophie.orgservice.grpc.OrgServiceGrpc;
import org.sophie.security.access.AccessGuard;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

/**
 * Registers the shared {@link AccessGuard} bean. Conditional on both the gRPC client starter AND
 * Org Service's generated stub being on the classpath — every service in scope for it already
 * depends on {@code sophie-protos} for other RPCs, but this guard costs nothing on a service that
 * doesn't (there are none today, but the condition costs nothing either).
 */
@AutoConfiguration
@AutoConfigureAfter(SophieSecurityAutoConfiguration.class)
@ConditionalOnClass({GrpcClient.class, OrgServiceGrpc.class})
public class SophieSecurityAccessAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public AccessGuard accessGuard(@GrpcClient("org-service") OrgServiceGrpc.OrgServiceBlockingStub orgServiceStub) {
        return new AccessGuard(orgServiceStub);
    }
}

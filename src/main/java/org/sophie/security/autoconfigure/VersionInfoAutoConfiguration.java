package org.sophie.security.autoconfigure;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.actuate.info.Info;
import org.springframework.boot.actuate.info.InfoContributor;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

/**
 * Five services silently running builds against a stale {@code sophie-common-security}/{@code
 * sophie-protos} cost three separate diagnosis sessions before anyone thought to check classpath
 * versions directly. This makes the two versions every service actually resolved impossible to miss:
 * one line at startup, and the same two values on {@code /actuator/info} for {@code
 * scripts/version-matrix.sh} to query live.
 *
 * <p>Reads {@code Implementation-Version} from each jar's own manifest (see both projects'
 * {@code jar { manifest { ... } } } blocks) rather than a hand-maintained constant, so this can never
 * itself drift from what got built.
 */
@AutoConfiguration
public class VersionInfoAutoConfiguration {

    private static final Logger log = LoggerFactory.getLogger(VersionInfoAutoConfiguration.class);

    // A stable, always-generated class from sophie-protos' org_service.proto — every service depends
    // on sophie-protos for gRPC stubs, but this library only ever declares it compileOnly (see
    // AccessGuard), so this class must be looked up reflectively rather than referenced directly; a
    // service that somehow lacks sophie-protos entirely gets "unknown" instead of a startup failure.
    private static final String PROTOS_MARKER_CLASS = "org.sophie.orgservice.grpc.OrgServiceGrpc";

    static String resolveCommonSecurityVersion() {
        String version = VersionInfoAutoConfiguration.class.getPackage().getImplementationVersion();
        return version != null ? version : "unknown";
    }

    static String resolveProtosVersion() {
        try {
            String version = Class.forName(PROTOS_MARKER_CLASS).getPackage().getImplementationVersion();
            return version != null ? version : "unknown";
        } catch (ClassNotFoundException e) {
            return "unknown";
        }
    }

    @Bean
    @ConditionalOnMissingBean
    public VersionStartupLogger versionStartupLogger() {
        return new VersionStartupLogger();
    }

    static final class VersionStartupLogger implements InitializingBean {
        @Override
        public void afterPropertiesSet() {
            log.info("Resolved shared library versions: sophie-common-security={}, sophie-protos={}",
                    resolveCommonSecurityVersion(), resolveProtosVersion());
        }
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnClass(InfoContributor.class)
    public InfoContributor sophieVersionInfoContributor() {
        return (Info.Builder builder) -> builder.withDetail("sophie", java.util.Map.of(
                "commonSecurityVersion", resolveCommonSecurityVersion(),
                "protosVersion", resolveProtosVersion()));
    }
}

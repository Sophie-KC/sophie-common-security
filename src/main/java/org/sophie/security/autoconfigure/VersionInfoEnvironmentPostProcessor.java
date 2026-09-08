package org.sophie.security.autoconfigure;

import java.util.Map;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;

/**
 * Runs during environment preparation, well before any {@code @AutoConfiguration} bean is created —
 * {@code management.endpoints.web.exposure.include} has to be set this early to affect actuator's own
 * autoconfiguration, which decides endpoint exposure around the same phase {@link
 * VersionInfoAutoConfiguration}'s beans would otherwise be created in (unreliable ordering between two
 * unrelated autoconfiguration classes).
 *
 * <p>Added last ({@code addLast}) so any service that already configures
 * {@code management.endpoints.web.exposure.include} itself keeps its own value — this only supplies a
 * default so {@code /actuator/info} (and {@code /actuator/health}, the one endpoint on by default) are
 * reachable for {@code scripts/version-matrix.sh} without every one of the 14 consumers needing to
 * repeat the same three words in their own application.yaml.
 */
public class VersionInfoEnvironmentPostProcessor implements EnvironmentPostProcessor {

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        environment.getPropertySources().addLast(new MapPropertySource(
                "sophieVersionInfoDefaults",
                Map.of("management.endpoints.web.exposure.include", "health,info")));
    }
}

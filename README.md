# sophie-common-security

Shared JWT/JWKS caller verification for every Sophie-KC gRPC service. Published as one Gradle artifact
— `org.sophie:sophie-common-security` — via GitHub Packages, same pattern as `sophie-protos`.

**Phase 1 (current): verified identity, non-enforcing.** A service that adds this dependency can
cryptographically verify who called it, but authorization still runs entirely on the existing
client-supplied identity fields (`requestedBy`/`requested_by`/`x-user-id`). Nothing rejects a call for
missing or mismatched identity — it only logs, via `IdentityComparisonLogger`, so those gaps can be
found and closed in phase 2.

## What it does

- **Server side** (`JwtServerInterceptor`, auto-registered as a `@GrpcGlobalServerInterceptor` when the
  service has a gRPC server): validates an inbound `authorization: Bearer <jwt>` against Keycloak's
  JWKS (cached at startup, no per-request network call), or an `x-internal-service-secret` for
  background/service-to-service calls. Populates a `UserPrincipal` or `ServicePrincipal` on the gRPC
  `Context`, readable via `SophieSecurityContext.current()` or the injectable `PrincipalAccessor` bean.
- **Client side** (`IdentityForwardingClientInterceptor`, auto-registered as a
  `@GrpcGlobalClientInterceptor` when the service has a gRPC client): forwards the original JWT (or,
  absent one, the inbound `x-user-id`/`x-org-role`, or the shared internal secret as a last resort) on
  every outbound call — applies broadly to every `@GrpcClient` stub, not per call site.
- **Comparison logging**: every inbound call logs whether the verified principal's `internalUserId`
  matches the `x-user-id` metadata the caller supplied. This measures identity *propagation*, not
  authorization correctness — see the class Javadoc before reading too much into any one log line.

## Adopting it in a service

```groovy
repositories {
    mavenLocal()
    maven {
        name = 'GitHubPackages'
        url = uri("https://maven.pkg.github.com/${project.findProperty('gpr.owner') ?: 'Sophie-KC'}/sophie-protos")
        credentials { /* ... */ }
    }
    // GitHub Packages registries are per-repository — this needs its own entry, distinct from the one above.
    maven {
        name = 'GitHubPackagesSecurity'
        url = uri("https://maven.pkg.github.com/${project.findProperty('gpr.owner') ?: 'Sophie-KC'}/sophie-common-security")
        credentials {
            username = project.findProperty('gpr.user') ?: System.getenv('GITHUB_ACTOR')
            password = project.findProperty('gpr.key') ?: System.getenv('GITHUB_TOKEN')
        }
    }
    mavenCentral()
}

dependencies {
    implementation 'org.sophie:sophie-common-security:0.1.0'
}
```

```yaml
keycloak:
  jwt:
    jwk-set-uri: ${KEYCLOAK_JWK_SET_URI:http://localhost:8080/realms/team-collab-platform-local/protocol/openid-connect/certs}
    issuer-uri: ${KEYCLOAK_ISSUER_URI:http://localhost:8080/realms/team-collab-platform-local}

sophie:
  security:
    service-name: <this-service's-name>   # e.g. task-service
    internal:
      shared-secret: ${SOPHIE_INTERNAL_SHARED_SECRET}
```

No handler code, no proto changes. Auto-configuration wires the interceptor(s) that apply to whatever
net.devh starter (server, client, or both) the service already has on its classpath.

## Build & publish locally

```bash
./gradlew publishToMavenLocal
```

## Why not Spring Security's `NimbusJwtDecoder`?

`JwtVerifier` is built directly on Nimbus rather than `spring-boot-starter-oauth2-resource-server` (or
even the bare `spring-security-oauth2-jose` + `-web`/`-config` combination), so this library never puts
`spring-security-web`/`spring-security-config` on a consumer's classpath. Several services run `webmvc`
solely to serve the actuator health endpoint for k8s probes — accidentally activating Spring Boot's
default HTTP security auto-configuration there would break liveness/readiness probes, well outside what
adding an identity-verification library should ever touch.

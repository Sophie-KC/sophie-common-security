package org.sophie.security.autoconfigure;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "sophie.security")
public class SophieSecurityProperties {

    /** This service's own name, asserted as the caller identity on outbound internal-secret calls. */
    private String serviceName;

    private Internal internal = new Internal();

    @Data
    public static class Internal {
        /** Shared secret every service presents on calls with no end-user behind them. Distributed
         *  identically to all services via the on-prem install script / deployment secrets. */
        private String sharedSecret;
    }
}

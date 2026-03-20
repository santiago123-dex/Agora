package backend.agoragateway.config;

import java.util.ArrayList;
import java.util.List;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "gateway.auth")
@Data
public class GatewayAuthProperties {

    // Whitelist de rutas públicas que no pasan por validación JWT
    private List<String> publicPaths = new ArrayList<>();

}

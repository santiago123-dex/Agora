package backend.agoragateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
//Con esta definimos el paquete base que va a escanear
@ConfigurationPropertiesScan
public class AgoraGatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(AgoraGatewayApplication.class, args);
    }

}

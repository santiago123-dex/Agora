package backend.workspace.config;

import org.springframework.web.filter.CorsFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
public class CorsConfig {
    // El @Bean Crea un componente que Spring usara automaticamente
    @Bean
    // El CorsFilter es un filtro que intercepta todas la peticiones HTTP
    public CorsFilter corsFilter(){
        // Objeto donde se definen las reglas CORS:
        // qué orígenes pueden acceder, métodos permitidos, headers, etc.
        CorsConfiguration config = new CorsConfiguration();
        // Contenedor que asocia rutas URL con una configuración CORS específica
        // (ej: /api/** -> usar config)
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();

        //Permite las credenciales
        config.setAllowCredentials(true);
        // Lista de origenes permitidos, va a devolver un array
        config.setAllowedOrigins(Arrays.asList(
                "http://localhost:3000",  // React
                "http://localhost:4200"
        ));
        // permite todos lo headers
        config.setAllowedHeaders(Arrays.asList("*"));
        // Lista de metodos HTTP permitidos
        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));

        //Aplica la configuracion de los CORS a todos los endpoints que empiecen con /api/
        source.registerCorsConfiguration("/api/**", config);
        // Crea y retorna el filtro CORS con toda la configuración
        return new CorsFilter(source);
    }
}

package backend.agoragateway.auth;

import backend.agoragateway.auth.dto.TokenValidationRequest;
import backend.agoragateway.auth.dto.TokenValidationResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

@Component
public class AuthValidationClient {

    private final WebClient webClient;

    public AuthValidationClient(
            WebClient.Builder builder,
            @Value("${services.auth.base-url}") String authBaseUrl
    ) {
        this.webClient = builder.baseUrl(authBaseUrl).build();
    }

    public Mono<TokenValidationResponse> validateAccessToken(String token) {
        return webClient
                .post()
                // Contract defined by Agora-Auth
                .uri("/public/auth/validate")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(new TokenValidationRequest(token))
                .retrieve()
                // Token invalid/expired
                .onStatus(HttpStatus.UNAUTHORIZED::equals, response -> Mono.error(new InvalidTokenException()))
                .bodyToMono(TokenValidationResponse.class);
    }

    public static class InvalidTokenException extends RuntimeException {
    }
}

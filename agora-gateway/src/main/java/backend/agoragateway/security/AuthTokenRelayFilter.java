package backend.agoragateway.security;

import backend.agoragateway.auth.AuthValidationClient;
import backend.agoragateway.auth.dto.TokenValidationResponse;
import backend.agoragateway.config.GatewayAuthProperties;
import java.util.List;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class AuthTokenRelayFilter implements GlobalFilter, Ordered {

    private static final String BEARER_PREFIX = "Bearer ";

    private final AuthValidationClient authValidationClient;
    private final GatewayAuthProperties gatewayAuthProperties;

    public AuthTokenRelayFilter(
            AuthValidationClient authValidationClient,
            GatewayAuthProperties gatewayAuthProperties
    ) {
        this.authValidationClient = authValidationClient;
        this.gatewayAuthProperties = gatewayAuthProperties;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        // Public endpoints bypass token validation
        if (isPublicPath(path, gatewayAuthProperties.getPublicPaths())) {
            return chain.filter(exchange);
        }

        // Protected endpoints must provide Bearer token
        String authorization = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authorization == null || !authorization.startsWith(BEARER_PREFIX) || authorization.length() <= BEARER_PREFIX.length()) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String token = authorization.substring(BEARER_PREFIX.length());

        return authValidationClient
                .validateAccessToken(token)
                // Forward identity context to downstream services
                .flatMap(validation -> chain.filter(withIdentityHeaders(exchange, validation)))
                .onErrorResume(AuthValidationClient.InvalidTokenException.class, ignored -> unauthorized(exchange))
                .onErrorResume(ignored -> unauthorized(exchange));
    }

    @Override
    public int getOrder() {
        return -100;
    }

    private boolean isPublicPath(String path, List<String> publicPaths) {
        return publicPaths.stream().anyMatch(path::startsWith);
    }

    private ServerWebExchange withIdentityHeaders(
            ServerWebExchange exchange,
            TokenValidationResponse validation
    ) {
        return exchange
                .mutate()
                .request(request -> request.headers(headers -> {
                    headers.set("X-User-Id", validation.user_id());
                    headers.set("X-Session-Id", validation.session_id());
                }))
                .build();
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }
}

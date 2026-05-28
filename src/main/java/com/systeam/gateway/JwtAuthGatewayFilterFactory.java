package com.systeam.gateway;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

@Component
public class JwtAuthGatewayFilterFactory
        extends AbstractGatewayFilterFactory<Object> {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthGatewayFilterFactory.class);

    private final AuthServiceClient authServiceClient;

    public JwtAuthGatewayFilterFactory(AuthServiceClient authServiceClient) {
        super(Object.class);
        this.authServiceClient = authServiceClient;
    }

    @Override
    public String name() {
        return "JwtAuth";
    }

    @Override
    public GatewayFilter apply(Object config) {
        return (exchange, chain) -> {
            String authHeader = exchange.getRequest()
                    .getHeaders()
                    .getFirst("Authorization");

            // Sin token: pasa sin inyectar headers
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return chain.filter(exchange);
            }

            // Validamos el token llamando al Auth Service
            return authServiceClient.validate(authHeader)
                    .map(user -> {
                        ServerHttpRequest mutatedRequest = exchange.getRequest()
                                .mutate()
                                .headers(h -> h.remove("Authorization"))
                                .header("X-User-Id", user.userId().toString())
                                .header("X-User-Email", user.email())
                                .header("X-User-Roles",
                                        String.join(",", user.roles()))
                                .header("X-User-Permissions",
                                        String.join(",", user.permissions()))
                                .build();

                        log.debug("Usuario {} autenticado via Gateway",
                                user.userId());

                        return chain.filter(
                                exchange.mutate()
                                        .request(mutatedRequest)
                                        .build());
                    })
                    .orElseGet(() -> {
                        log.warn("Token rechazado por Auth Service");
                        exchange.getResponse().setStatusCode(
                                org.springframework.http.HttpStatus.UNAUTHORIZED);
                        return exchange.getResponse().setComplete();
                    });
        };
    }
}

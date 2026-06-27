package com.systeam.gateway;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Optional;

@Component
public class AuthServiceClient {

    private static final Logger log = LoggerFactory.getLogger(AuthServiceClient.class);

    private final WebClient webClient;

    public AuthServiceClient(@Value("${auth.service.url}") String authServiceUrl) {
        this.webClient = WebClient.builder()
                .baseUrl(authServiceUrl)
                .build();
    }

    public Mono<Optional<ValidatedUser>> validate(String authorizationHeader) {
        return webClient.get()
                .uri("/auth/validate")
                .header("Authorization", authorizationHeader)
                .retrieve()
                .bodyToMono(ValidatedUser.class)
                .map(Optional::of)
                .retry(3)
                .onErrorResume(e -> {
                    log.warn("Auth service call failed: {}", e.getMessage());
                    return Mono.just(Optional.empty());
                });
    }
}

package com.iam.auth.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.net.URI;

@Component
@Slf4j
public class OAuth2AuthenticationFailureHandler implements ServerAuthenticationFailureHandler {

    @Value("${oauth2.failure-redirect-url:http://localhost:3000/login?error=oauth2_failed}")
    private String failureRedirectUrl;

    @Override
    public Mono<Void> onAuthenticationFailure(WebFilterExchange webFilterExchange, AuthenticationException exception) {
        log.error("OAuth2 authentication failed: {}", exception.getMessage());

        String redirectUrl = String.format("%s&message=%s",
                failureRedirectUrl,
                exception.getMessage().replaceAll(" ", "%20"));

        webFilterExchange.getExchange().getResponse()
                .setStatusCode(org.springframework.http.HttpStatus.FOUND);
        webFilterExchange.getExchange().getResponse().getHeaders()
                .setLocation(URI.create(redirectUrl));

        return webFilterExchange.getExchange().getResponse().setComplete();
    }
}

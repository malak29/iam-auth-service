package com.iam.auth.config;

import com.iam.auth.security.CustomOAuth2User;
import com.iam.common.jwt.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.time.LocalDateTime;

@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2AuthenticationSuccessHandler implements ServerAuthenticationSuccessHandler {

    private final JwtTokenProvider jwtTokenProvider;

    @Value("${oauth2.success-redirect-url:http://localhost:3000/auth/callback}")
    private String successRedirectUrl;

    @Override
    public Mono<Void> onAuthenticationSuccess(WebFilterExchange webFilterExchange, Authentication authentication) {
        CustomOAuth2User oAuth2User = (CustomOAuth2User) authentication.getPrincipal();

        log.info("OAuth2 authentication successful for user: {}", oAuth2User.getUser().getEmail());

        return jwtTokenProvider.generateToken(oAuth2User.getUser().getUserId().toString())
                .flatMap(accessToken ->
                        jwtTokenProvider.generateRefreshToken(oAuth2User.getUser().getUsername())
                                .map(refreshToken -> {
                                    // Build redirect URL with tokens
                                    String redirectUrl = String.format("%s?access_token=%s&refresh_token=%s&user_id=%s&provider=%s",
                                            successRedirectUrl,
                                            accessToken,
                                            refreshToken,
                                            oAuth2User.getUser().getUserId(),
                                            authentication.getDetails()
                                    );

                                    webFilterExchange.getExchange().getResponse()
                                            .setStatusCode(org.springframework.http.HttpStatus.FOUND);
                                    webFilterExchange.getExchange().getResponse().getHeaders()
                                            .setLocation(URI.create(redirectUrl));

                                    return null;
                                })
                )
                .then(webFilterExchange.getExchange().getResponse().setComplete())
                .doOnSuccess(unused -> log.info("OAuth2 user redirected with tokens"));
    }
}
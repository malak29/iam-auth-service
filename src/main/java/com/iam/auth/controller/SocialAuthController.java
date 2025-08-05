package com.iam.auth.controller;

import com.iam.auth.config.ApiRoutes;
import com.iam.auth.dto.SocialLoginResponse;
import com.iam.auth.service.SocialAuthService;
import com.iam.common.response.ApiResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping(ApiRoutes.AUTH + "/social")
@RequiredArgsConstructor
@Slf4j
public class SocialAuthController {

    private final SocialAuthService socialAuthService;

    @GetMapping("/google/url")
    public Mono<ResponseEntity<ApiResponse<String>>> getGoogleAuthUrl() {
        return socialAuthService.getGoogleAuthUrl()
                .map(url -> ResponseEntity.ok(ApiResponse.success(url, "Google auth URL generated")));
    }

    @GetMapping("/github/url")
    public Mono<ResponseEntity<ApiResponse<String>>> getGitHubAuthUrl() {
        return socialAuthService.getGitHubAuthUrl()
                .map(url -> ResponseEntity.ok(ApiResponse.success(url, "GitHub auth URL generated")));
    }

    @GetMapping("/facebook/url")
    public Mono<ResponseEntity<ApiResponse<String>>> getFacebookAuthUrl() {
        return socialAuthService.getFacebookAuthUrl()
                .map(url -> ResponseEntity.ok(ApiResponse.success(url, "Facebook auth URL generated")));
    }

    @PostMapping("/callback")
    public Mono<ResponseEntity<ApiResponse<SocialLoginResponse>>> handleCallback(
            @RequestParam String code,
            @RequestParam String state,
            @RequestParam String provider) {

        log.info("Processing OAuth2 callback for provider: {}", provider);

        return socialAuthService.processCallback(code, state, provider)
                .map(response -> ResponseEntity.ok(ApiResponse.success(response, "Social login successful")))
                .onErrorResume(error -> {
                    log.error("OAuth2 callback failed: {}", error.getMessage());
                    return Mono.just(ResponseEntity.badRequest()
                            .body(ApiResponse.error("Social login failed: " + error.getMessage())));
                });
    }

    @GetMapping("/providers")
    public Mono<ResponseEntity<ApiResponse<Object>>> getAvailableProviders() {
        return socialAuthService.getAvailableProviders()
                .map(providers -> ResponseEntity.ok(ApiResponse.success(providers, "Available social providers")));
    }
}
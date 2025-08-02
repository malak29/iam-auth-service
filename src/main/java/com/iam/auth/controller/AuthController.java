package com.iam.auth.controller;

import com.iam.auth.config.ApiRoutes;
import com.iam.auth.dto.*;
import com.iam.auth.service.AuthService;
import com.iam.common.response.ApiResponse;
import com.iam.common.jwt.JwtTokenProvider;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping(ApiRoutes.AUTH)
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = "*")
public class AuthController {

    private final AuthService authService;
    private final JwtTokenProvider jwtTokenProvider;

    @PostMapping(ApiRoutes.LOGIN)
    public Mono<ResponseEntity<ApiResponse<LoginResponse>>> login(@Valid @RequestBody Mono<LoginRequest> loginRequestMono) {
        return loginRequestMono
                .doOnNext(request -> log.info("Login request received for email: {}", request.getEmail()))
                .flatMap(authService::login)
                .map(loginResponse -> ResponseEntity.ok(ApiResponse.success(loginResponse, "Login successful")))
                .doOnSuccess(response -> log.info("Login request completed"));
    }

    @PostMapping(ApiRoutes.REFRESH)
    public Mono<ResponseEntity<ApiResponse<LoginResponse>>> refreshToken(@Valid @RequestBody Mono<RefreshTokenRequest> refreshRequestMono) {
        return refreshRequestMono
                .doOnNext(request -> log.info("Token refresh request received"))
                .flatMap(authService::refreshToken)
                .map(loginResponse -> ResponseEntity.ok(ApiResponse.success(loginResponse, "Token refreshed successfully")))
                .doOnSuccess(response -> log.info("Token refresh completed"));
    }

    @PostMapping(ApiRoutes.LOGOUT)
    public Mono<ResponseEntity<ApiResponse<String>>> logout(@Valid @RequestBody Mono<LogoutRequest> logoutRequestMono) {
        return logoutRequestMono
                .doOnNext(request -> log.info("Logout request received"))
                .flatMap(authService::logout)
                .map(ResponseEntity::ok)
                .doOnSuccess(response -> log.info("Logout completed"));
    }

    @GetMapping(ApiRoutes.HEALTH)
    public Mono<ResponseEntity<ApiResponse<String>>> health() {
        return Mono.just(ResponseEntity.ok(
                ApiResponse.success("OK", "Auth service is running")
        ));
    }

    @PostMapping(ApiRoutes.VALIDATE)
    public Mono<ResponseEntity<ApiResponse<String>>> validateToken(@RequestHeader("Authorization") String authHeader) {
        log.info("Token validation request received");

        if (!authHeader.startsWith("Bearer ")) {
            return Mono.just(ResponseEntity.badRequest().body(
                    ApiResponse.error("Invalid authorization header format")
            ));
        }

        String token = authHeader.substring(7);

        return jwtTokenProvider.validateToken(token)
                .map(claims -> ResponseEntity.ok(ApiResponse.success("Valid", "Token is valid")))
                .onErrorReturn(ResponseEntity.badRequest().body(ApiResponse.error("Invalid token")))
                .doOnSuccess(response -> log.info("Token validation completed"));
    }
}
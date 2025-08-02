package com.iam.auth.service;

import com.iam.auth.dto.*;
import com.iam.common.repository.UserRepository;
import com.iam.common.jwt.JwtTokenProvider;
import com.iam.common.response.ApiResponse;
import com.iam.common.exception.AuthenticationException;
import com.iam.common.exception.CustomExceptions;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final AuthValidationService authValidationService;
    private final TokenService tokenService;
    private final UserAccountService userAccountService;
    private final AuthUtilityService authUtilityService;

    public Mono<LoginResponse> login(LoginRequest loginRequest) {
        log.info("Login attempt for email: {}", loginRequest.getEmail());

        return authValidationService.validateLoginInput(loginRequest)
                .then(userRepository.findByEmail(loginRequest.getEmail()))
                .switchIfEmpty(Mono.error(new AuthenticationException("Invalid email or password")))
                .flatMap(user -> authValidationService.validateUserAccount(user)
                        .then(authValidationService.validatePassword(loginRequest.getPassword(), user))
                        .then(userAccountService.resetFailedLoginAttempts(user))
                        .then(userAccountService.updateLastLogin(user))
                        .then(tokenService.generateTokensAndResponse(user))
                )
                .doOnSuccess(response -> log.info("Successful login for email: {}", loginRequest.getEmail()))
                .onErrorMap(ex -> {
                    if (ex instanceof AuthenticationException) {
                        return ex;
                    }
                    log.error("Unexpected error during login for email {}: {}", loginRequest.getEmail(), ex.getMessage());
                    return new AuthenticationException("An unexpected error occurred during login");
                });
    }

    public Mono<LoginResponse> refreshToken(RefreshTokenRequest refreshRequest) {
        log.info("Token refresh attempt");

        return authValidationService.validateRefreshTokenInput(refreshRequest)
                .then(tokenService.extractUserIdFromRefreshToken(refreshRequest.getRefreshToken()))
                .flatMap(userId -> tokenService.validateStoredRefreshToken(userId, refreshRequest.getRefreshToken())
                        .then(userRepository.findById(userId))
                        .switchIfEmpty(Mono.error(new CustomExceptions.UserNotFoundException("User not found")))
                        .flatMap(user -> authValidationService.validateActiveUser(user)
                                .then(tokenService.generateTokensAndResponse(user))
                        )
                )
                .doOnSuccess(response -> log.info("Token refreshed successfully"))
                .onErrorMap(ex -> {
                    if (ex instanceof AuthenticationException) {
                        return ex;
                    }
                    log.error("Unexpected error during token refresh: {}", ex.getMessage());
                    return new AuthenticationException("An unexpected error occurred during token refresh");
                });
    }

    public Mono<ApiResponse<String>> logout(LogoutRequest logoutRequest) {
        log.info("Logout attempt");

        return authValidationService.validateLogoutInput(logoutRequest)
                .then(jwtTokenProvider.extractUsername(logoutRequest.getAccessToken()))
                .map(UUID::fromString)
                .flatMap(userId -> tokenService.removeRefreshToken(userId)
                        .then(tokenService.blacklistToken(logoutRequest.getAccessToken()))
                        .then(Mono.just(ApiResponse.<String>success("Logged out successfully"))) // ADD <String>
                )
                .doOnSuccess(response -> log.info("User logged out successfully"))
                .onErrorMap(ex -> {
                    if (ex instanceof AuthenticationException) {
                        return ex;
                    }
                    log.error("Unexpected error during logout: {}", ex.getMessage());
                    return new AuthenticationException("An unexpected error occurred during logout");
                });
    }
}
package com.iam.auth.service;

import com.iam.auth.dto.LoginRequest;
import com.iam.auth.dto.LogoutRequest;
import com.iam.auth.dto.RefreshTokenRequest;
import com.iam.common.model.User;
import com.iam.common.exception.AuthenticationException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthValidationService {

    private final PasswordEncoder passwordEncoder;
    private final UserAccountService userAccountService;

    public Mono<Void> validateLoginInput(LoginRequest request) {
        if (request.getEmail() == null || request.getPassword() == null) {
            return Mono.error(new AuthenticationException("Email and password are required"));
        }
        return Mono.empty();
    }

    public Mono<Void> validateUserAccount(User user) {
        if (Boolean.TRUE.equals(user.getAccountLocked())) {
            log.warn("Login attempt on locked account: {}", user.getEmail());
            return Mono.error(new AuthenticationException("Account is locked. Please contact support."));
        }
        if (!user.getUserStatusId().equals(1)) {
            log.warn("Login attempt on inactive account: {}", user.getEmail());
            return Mono.error(new AuthenticationException("Account is not active"));
        }
        return Mono.empty();
    }

    public Mono<Void> validatePassword(String rawPassword, User user) {
        return Mono.fromCallable(() -> {
            if (user.getHashedPassword() == null ||
                    !passwordEncoder.matches(rawPassword, user.getHashedPassword())) {
                userAccountService.handleFailedLogin(user).subscribe(); // Fire and forget
                throw new AuthenticationException("Invalid email or password");
            }
            return null;
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }

    public Mono<Void> validateActiveUser(User user) {
        if (!user.getUserStatusId().equals(1)) {
            return Mono.error(new AuthenticationException("User account is not active"));
        }
        return Mono.empty();
    }

    public Mono<Void> validateRefreshTokenInput(RefreshTokenRequest request) {
        if (request.getRefreshToken() == null || request.getRefreshToken().trim().isEmpty()) {
            return Mono.error(new AuthenticationException("Refresh token is required"));
        }
        return Mono.empty();
    }

    public Mono<Void> validateLogoutInput(LogoutRequest request) {
        if (request.getAccessToken() == null || request.getAccessToken().trim().isEmpty()) {
            return Mono.error(new AuthenticationException("Access token is required"));
        }
        return Mono.empty();
    }
}
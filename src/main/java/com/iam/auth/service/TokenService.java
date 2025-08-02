package com.iam.auth.service;

import com.iam.auth.dto.LoginResponse;
import com.iam.common.model.User;
import com.iam.common.jwt.JwtTokenProvider;
import com.iam.common.exception.AuthenticationException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class TokenService {

    private final JwtTokenProvider jwtTokenProvider;
    private final ReactiveRedisTemplate<String, String> reactiveRedisTemplate;
    private final AuthUtilityService authUtilityService;

    @Value("${jwt.refresh-expiration-ms:604800000}")
    private long refreshTokenExpirationMs;

    public Mono<LoginResponse> generateTokensAndResponse(User user) {
        return Mono.zip(
                        jwtTokenProvider.generateToken(user.getUserId().toString()),
                        generateRefreshTokenMono(user.getUserId())
                )
                .flatMap(tokens -> {
                    String accessToken = tokens.getT1();
                    String refreshToken = tokens.getT2();

                    return storeRefreshToken(user.getUserId(), refreshToken)
                            .then(Mono.just(LoginResponse.builder()
                                    .accessToken(accessToken)
                                    .refreshToken(refreshToken)
                                    .tokenType("Bearer")
                                    .expiresIn(jwtTokenProvider.getExpirationTime())
                                    .userInfo(authUtilityService.buildUserInfo(user))
                                    .loginAt(LocalDateTime.now())
                                    .build()));
                });
    }

    public Mono<String> generateRefreshTokenMono(UUID userId) {
        return Mono.fromCallable(() ->
                userId.toString() + "_" + System.currentTimeMillis() + "_" + UUID.randomUUID().toString()
        );
    }

    public Mono<Void> storeRefreshToken(UUID userId, String refreshToken) {
        return reactiveRedisTemplate.opsForValue()
                .set("refresh_token:" + userId, refreshToken, Duration.ofMillis(refreshTokenExpirationMs))
                .then();
    }

    public Mono<UUID> extractUserIdFromRefreshToken(String refreshToken) {
        return Mono.fromCallable(() -> {
            String[] parts = refreshToken.split("_");
            if (parts.length != 3) {
                throw new AuthenticationException("Invalid refresh token format");
            }
            return UUID.fromString(parts[0]);
        });
    }

    public Mono<Void> validateStoredRefreshToken(UUID userId, String refreshToken) {
        return reactiveRedisTemplate.opsForValue().get("refresh_token:" + userId)
                .switchIfEmpty(Mono.error(new AuthenticationException("Invalid or expired refresh token")))
                .flatMap(storedToken -> {
                    if (!storedToken.equals(refreshToken)) {
                        return Mono.error(new AuthenticationException("Invalid or expired refresh token"));
                    }
                    return Mono.empty();
                });
    }

    public Mono<Void> removeRefreshToken(UUID userId) {
        return reactiveRedisTemplate.delete("refresh_token:" + userId).then();
    }

    public Mono<Void> blacklistToken(String accessToken) {
        return reactiveRedisTemplate.opsForValue()
                .set("blacklist:" + accessToken, "true", Duration.ofMillis(jwtTokenProvider.getExpirationTime()))
                .then();
    }
}
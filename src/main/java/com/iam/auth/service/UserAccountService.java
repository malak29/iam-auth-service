package com.iam.auth.service;

import com.iam.common.model.User;
import com.iam.common.repository.UserRepository;
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
public class UserAccountService {

    private final UserRepository userRepository;
    private final ReactiveRedisTemplate<String, String> reactiveRedisTemplate;

    @Value("${auth.max-login-attempts:5}")
    private int maxLoginAttempts;

    @Value("${auth.account-lock-duration-minutes:30}")
    private int accountLockDurationMinutes;

    public Mono<Void> resetFailedLoginAttempts(User user) {
        if (user.getFailedLoginAttempts() != null && user.getFailedLoginAttempts() > 0) {
            return userRepository.updateFailedLoginAttempts(user.getUserId(), 0).then();
        }
        return Mono.empty();
    }

    public Mono<Void> updateLastLogin(User user) {
        return userRepository.updateLastLogin(user.getUserId(), LocalDateTime.now()).then();
    }

    public Mono<Void> handleFailedLogin(User user) {
        int newAttempts = (user.getFailedLoginAttempts() != null ? user.getFailedLoginAttempts() : 0) + 1;

        return userRepository.updateFailedLoginAttempts(user.getUserId(), newAttempts)
                .then(Mono.defer(() -> {
                    if (newAttempts >= maxLoginAttempts) {
                        return userRepository.updateAccountLocked(user.getUserId(), true)
                                .then(scheduleAccountUnlock(user.getUserId()))
                                .doOnSuccess(unused -> log.warn("Account locked due to failed login attempts: {}", user.getEmail()));
                    }
                    return Mono.empty();
                }));
    }

    private Mono<Void> scheduleAccountUnlock(UUID userId) {
        return reactiveRedisTemplate.opsForValue()
                .set("unlock_account:" + userId, "true", Duration.ofMinutes(accountLockDurationMinutes))
                .then()
                .doOnSuccess(unused -> log.debug("Account unlock scheduled for user: {}", userId));
    }
}
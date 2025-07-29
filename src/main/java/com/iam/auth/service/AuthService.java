package com.iam.auth.service;

import com.iam.auth.dto.*;
import com.iam.common.model.User;
import com.iam.common.repository.UserRepository;
import com.iam.common.jwt.JwtTokenProvider;
import com.iam.common.response.ApiResponse;
import com.iam.common.exception.AuthenticationException;
import com.iam.common.exception.CustomExceptions;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final RedisTemplate<String, String> redisTemplate;

    @Value("${auth.max-login-attempts:5}")
    private int maxLoginAttempts;

    @Value("${auth.account-lock-duration-minutes:30}")
    private int accountLockDurationMinutes;

    @Value("${jwt.refresh-expiration-ms:604800000}")
    private long refreshTokenExpirationMs;

    public LoginResponse login(LoginRequest loginRequest) {
        log.info("Login attempt for email: {}", loginRequest.getEmail());

        try {
            // Validate input
            if (loginRequest.getEmail() == null || loginRequest.getPassword() == null) {
                throw new AuthenticationException("Email and password are required");
            }

            // Find user by email
            User user = userRepository.findUserByEmail(loginRequest.getEmail())
                    .orElseThrow(() -> new AuthenticationException("Invalid email or password"));

            // Check if account is locked
            if (Boolean.TRUE.equals(user.getAccountLocked())) {
                log.warn("Login attempt on locked account: {}", user.getEmail());
                throw new AuthenticationException("Account is locked. Please contact support.");
            }

            // Check if account is active (assuming 1 = ACTIVE status)
            if (!user.getUserStatusId().equals(1)) {
                log.warn("Login attempt on inactive account: {}", user.getEmail());
                throw new AuthenticationException("Account is not active");
            }

            // Verify password
            if (user.getHashedPassword() == null ||
                    !passwordEncoder.matches(loginRequest.getPassword(), user.getHashedPassword())) {
                handleFailedLogin(user);
                throw new AuthenticationException("Invalid email or password");
            }

            // Reset failed login attempts on successful login
            try {
                if (user.getFailedLoginAttempts() != null && user.getFailedLoginAttempts() > 0) {
                    userRepository.updateUserFailedLoginAttempts(user.getUserId(), 0);
                }
            } catch (Exception e) {
                log.error("Failed to reset login attempts for user {}: {}", user.getUserId(), e.getMessage());
            }

            // Update last login time
            LocalDateTime loginTime = LocalDateTime.now();
            try {
                userRepository.updateUserLastLogin(user.getUserId(), loginTime);
            } catch (Exception e) {
                log.error("Failed to update last login for user {}: {}", user.getUserId(), e.getMessage());
            }

            // Generate tokens
            String accessToken;
            String refreshToken;
            try {
                accessToken = jwtTokenProvider.generateToken(user.getUserId().toString());
                refreshToken = generateRefreshToken(user.getUserId());
            } catch (Exception e) {
                log.error("Failed to generate tokens for user {}: {}", user.getUserId(), e.getMessage());
                throw new AuthenticationException("Failed to generate authentication tokens");
            }

            // Store refresh token in Redis
            try {
                storeRefreshToken(user.getUserId(), refreshToken);
            } catch (Exception e) {
                log.error("Failed to store refresh token for user {}: {}", user.getUserId(), e.getMessage());
                throw new AuthenticationException("Failed to store session information");
            }

            log.info("Successful login for user: {}", user.getEmail());

            return LoginResponse.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .tokenType("Bearer")
                    .expiresIn(jwtTokenProvider.getExpirationTime())
                    .userInfo(buildUserInfo(user))
                    .loginAt(loginTime)
                    .build();

        } catch (AuthenticationException e) {
            log.error("Authentication failed for email {}: {}", loginRequest.getEmail(), e.getMessage());
            throw e;
        } catch (Exception e) {
            log.error("Unexpected error during login for email {}: {}", loginRequest.getEmail(), e.getMessage(), e);
            throw new AuthenticationException("An unexpected error occurred during login");
        }
    }

    public LoginResponse refreshToken(RefreshTokenRequest refreshRequest) {
        log.info("Token refresh attempt");

        try {
            String refreshToken = refreshRequest.getRefreshToken();

            // Validate refresh token format
            if (refreshToken == null || refreshToken.trim().isEmpty()) {
                throw new AuthenticationException("Refresh token is required");
            }

            if (!isValidRefreshTokenFormat(refreshToken)) {
                throw new AuthenticationException("Invalid refresh token format");
            }

            // Extract user ID from refresh token
            UUID userId;
            try {
                userId = extractUserIdFromRefreshToken(refreshToken);
            } catch (Exception e) {
                log.error("Failed to extract user ID from refresh token: {}", e.getMessage());
                throw new AuthenticationException("Invalid refresh token");
            }

            // Verify refresh token exists in Redis
            String storedToken;
            try {
                storedToken = redisTemplate.opsForValue().get("refresh_token:" + userId);
            } catch (Exception e) {
                log.error("Failed to retrieve refresh token from Redis for user {}: {}", userId, e.getMessage());
                throw new AuthenticationException("Failed to validate refresh token");
            }

            if (storedToken == null || !storedToken.equals(refreshToken)) {
                log.warn("Invalid refresh token for user: {}", userId);
                throw new AuthenticationException("Invalid or expired refresh token");
            }

            // Get user details
            User user;
            try {
                user = userRepository.findById(userId)
                        .orElseThrow(() -> new CustomExceptions.UserNotFoundException("User not found"));
            } catch (Exception e) {
                log.error("Failed to retrieve user {} from database: {}", userId, e.getMessage());
                throw new AuthenticationException("User validation failed");
            }

            // Check if user is still active
            if (!user.getUserStatusId().equals(1)) {
                log.warn("Token refresh attempt for inactive user: {}", user.getEmail());
                throw new AuthenticationException("User account is not active");
            }

            // Generate new tokens
            String newAccessToken;
            String newRefreshToken;
            try {
                newAccessToken = jwtTokenProvider.generateToken(user.getUserId().toString());
                newRefreshToken = generateRefreshToken(user.getUserId());
            } catch (Exception e) {
                log.error("Failed to generate new tokens for user {}: {}", userId, e.getMessage());
                throw new AuthenticationException("Failed to generate new tokens");
            }

            // Update refresh token in Redis
            try {
                storeRefreshToken(user.getUserId(), newRefreshToken);
            } catch (Exception e) {
                log.error("Failed to store new refresh token for user {}: {}", userId, e.getMessage());
                throw new AuthenticationException("Failed to update session");
            }

            log.info("Token refreshed successfully for user: {}", user.getEmail());

            return LoginResponse.builder()
                    .accessToken(newAccessToken)
                    .refreshToken(newRefreshToken)
                    .tokenType("Bearer")
                    .expiresIn(jwtTokenProvider.getExpirationTime())
                    .userInfo(buildUserInfo(user))
                    .loginAt(LocalDateTime.now())
                    .build();

        } catch (AuthenticationException e) {
            log.error("Token refresh failed: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            log.error("Unexpected error during token refresh: {}", e.getMessage(), e);
            throw new AuthenticationException("An unexpected error occurred during token refresh");
        }
    }

    public ApiResponse<String> logout(LogoutRequest logoutRequest) {
        log.info("Logout attempt");

        try {
            // Validate input
            if (logoutRequest.getAccessToken() == null || logoutRequest.getAccessToken().trim().isEmpty()) {
                throw new AuthenticationException("Access token is required");
            }

            // Extract user ID from access token
            String userIdStr;
            UUID userId;
            try {
                userIdStr = jwtTokenProvider.extractUsername(logoutRequest.getAccessToken());
                userId = UUID.fromString(userIdStr);
            } catch (Exception e) {
                log.error("Failed to extract user ID from access token: {}", e.getMessage());
                throw new AuthenticationException("Invalid access token");
            }

            // Remove refresh token from Redis
            try {
                Boolean deleted = redisTemplate.delete("refresh_token:" + userId);
                log.debug("Refresh token deletion result for user {}: {}", userId, deleted);
            } catch (Exception e) {
                log.error("Failed to delete refresh token for user {}: {}", userId, e.getMessage());
            }

            // Blacklist the access token
            try {
                blacklistToken(logoutRequest.getAccessToken());
            } catch (Exception e) {
                log.error("Failed to blacklist access token for user {}: {}", userId, e.getMessage());
            }

            log.info("User logged out successfully: {}", userId);
            return ApiResponse.success("Logged out successfully");

        } catch (AuthenticationException e) {
            log.error("Logout failed: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            log.error("Unexpected error during logout: {}", e.getMessage(), e);
            throw new AuthenticationException("An unexpected error occurred during logout");
        }
    }

    // Helper methods
    private void handleFailedLogin(User user) {
        try {
            int newAttempts = (user.getFailedLoginAttempts() != null ? user.getFailedLoginAttempts() : 0) + 1;
            userRepository.updateUserFailedLoginAttempts(user.getUserId(), newAttempts);

            if (newAttempts >= maxLoginAttempts) {
                try {
                    userRepository.updateUserAccountLocked(user.getUserId(), true);
                    log.warn("Account locked due to failed login attempts: {}", user.getEmail());
                    scheduleAccountUnlock(user.getUserId());
                } catch (Exception e) {
                    log.error("Failed to lock account for user {}: {}", user.getUserId(), e.getMessage());
                }
            }
        } catch (Exception e) {
            log.error("Failed to handle failed login for user {}: {}", user.getUserId(), e.getMessage());
        }
    }

    private LoginResponse.UserInfo buildUserInfo(User user) {
        return LoginResponse.UserInfo.builder()
                .userId(user.getUserId().toString())
                .email(user.getEmail())
                .username(user.getUsername())
                .name(user.getName())
                .orgId(user.getOrgId())
                .departmentId(user.getDepartmentId())
                .userType(getUserTypeName(user.getUserTypeId()))
                .userStatus(getUserStatusName(user.getUserStatusId()))
                .build();
    }

    private String generateRefreshToken(UUID userId) {
        return userId.toString() + "_" + System.currentTimeMillis() + "_" + UUID.randomUUID().toString();
    }

    private void storeRefreshToken(UUID userId, String refreshToken) {
        try {
            redisTemplate.opsForValue().set(
                    "refresh_token:" + userId,
                    refreshToken,
                    refreshTokenExpirationMs,
                    TimeUnit.MILLISECONDS
            );
            log.debug("Refresh token stored successfully for user: {}", userId);
        } catch (Exception e) {
            log.error("Failed to store refresh token in Redis for user {}: {}", userId, e.getMessage());
            throw new AuthenticationException("Failed to store session information");
        }
    }

    private boolean isValidRefreshTokenFormat(String token) {
        String[] parts = token.split("_");
        return parts.length == 3;
    }

    private UUID extractUserIdFromRefreshToken(String refreshToken) {
        try {
            return UUID.fromString(refreshToken.split("_")[0]);
        } catch (Exception e) {
            throw new AuthenticationException("Invalid refresh token format");
        }
    }

    private void blacklistToken(String accessToken) {
        try {
            long remainingTime = jwtTokenProvider.getExpirationTime();
            redisTemplate.opsForValue().set(
                    "blacklist:" + accessToken,
                    "true",
                    remainingTime,
                    TimeUnit.MILLISECONDS
            );
            log.debug("Access token blacklisted successfully");
        } catch (Exception e) {
            log.error("Failed to blacklist access token: {}", e.getMessage());
            throw new AuthenticationException("Failed to invalidate token");
        }
    }

    private void scheduleAccountUnlock(UUID userId) {
        try {
            redisTemplate.opsForValue().set(
                    "unlock_account:" + userId,
                    "true",
                    accountLockDurationMinutes,
                    TimeUnit.MINUTES
            );
            log.debug("Account unlock scheduled for user: {}", userId);
        } catch (Exception e) {
            log.error("Failed to schedule account unlock for user {}: {}", userId, e.getMessage());
        }
    }

    private String getUserTypeName(Integer userTypeId) {
        return switch (userTypeId) {
            case 1 -> "GUEST_USER";
            case 2 -> "DEPT_USER";
            case 3 -> "MANAGER";
            case 4 -> "DEPT_USER";
            case 5 -> "DEPT_HEAD";
            case 8 -> "ORG_ADMIN";
            case 10 -> "SUPER_ADMIN";
            default -> "UNKNOWN";
        };
    }

    private String getUserStatusName(Integer userStatusId) {
        return switch (userStatusId) {
            case 1 -> "ACTIVE";
            case 2 -> "INACTIVE";
            case 3 -> "PENDING";
            case 4 -> "SUSPENDED";
            case 5 -> "LOCKED";
            default -> "UNKNOWN";
        };
    }
}
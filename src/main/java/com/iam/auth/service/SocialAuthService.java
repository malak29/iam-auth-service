package com.iam.auth.service;

import com.iam.auth.dto.SocialLoginResponse;
import com.iam.common.model.User;
import com.iam.common.repository.UserRepository;
import com.iam.common.jwt.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class SocialAuthService {

    private final UserRepository userRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final WebClient.Builder webClientBuilder;

    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String googleClientId;

    @Value("${spring.security.oauth2.client.registration.google.client-secret}")
    private String googleClientSecret;

    @Value("${spring.security.oauth2.client.registration.github.client-id}")
    private String githubClientId;

    @Value("${spring.security.oauth2.client.registration.github.client-secret}")
    private String githubClientSecret;

    @Value("${oauth2.redirect-uri:http://localhost:8082/login/oauth2/code}")
    private String redirectUri;

    public Mono<String> getGoogleAuthUrl() {
        String scope = "openid email profile";
        String state = generateState();

        String authUrl = String.format(
                "https://accounts.google.com/o/oauth2/v2/auth?" +
                        "client_id=%s&" +
                        "redirect_uri=%s/google&" +
                        "scope=%s&" +
                        "response_type=code&" +
                        "state=%s",
                googleClientId, redirectUri, scope, state
        );

        return Mono.just(authUrl);
    }

    public Mono<String> getGitHubAuthUrl() {
        String scope = "user:email";
        String state = generateState();

        String authUrl = String.format(
                "https://github.com/login/oauth/authorize?" +
                        "client_id=%s&" +
                        "redirect_uri=%s/github&" +
                        "scope=%s&" +
                        "state=%s",
                githubClientId, redirectUri, scope, state
        );

        return Mono.just(authUrl);
    }

    public Mono<String> getFacebookAuthUrl() {
        String scope = "email,public_profile";
        String state = generateState();

        String authUrl = String.format(
                "https://www.facebook.com/v18.0/dialog/oauth?" +
                        "client_id=%s&" +
                        "redirect_uri=%s/facebook&" +
                        "scope=%s&" +
                        "response_type=code&" +
                        "state=%s",
                // Note: You'll need to add Facebook client ID to config
                "your-facebook-client-id", redirectUri, scope, state
        );

        return Mono.just(authUrl);
    }

    public Mono<SocialLoginResponse> processCallback(String code, String state, String provider) {
        log.info("Processing OAuth2 callback for provider: {}", provider);

        return exchangeCodeForToken(code, provider)
                .flatMap(accessToken -> getUserInfoFromProvider(accessToken, provider))
                .flatMap(userInfo -> processUserInfo(userInfo, provider))
                .flatMap(this::generateJwtTokens);
    }

    public Mono<Map<String, Object>> getAvailableProviders() {
        return Mono.just(Map.of(
                "google", Map.of(
                        "name", "Google",
                        "enabled", !googleClientId.isEmpty(),
                        "icon", "google",
                        "authUrl", "/api/v1/auth/social/google/url"
                ),
                "github", Map.of(
                        "name", "GitHub",
                        "enabled", !githubClientId.isEmpty(),
                        "icon", "github",
                        "authUrl", "/api/v1/auth/social/github/url"
                ),
                "facebook", Map.of(
                        "name", "Facebook",
                        "enabled", false, // Add when configured
                        "icon", "facebook",
                        "authUrl", "/api/v1/auth/social/facebook/url"
                )
        ));
    }

    private Mono<String> exchangeCodeForToken(String code, String provider) {
        WebClient webClient = webClientBuilder.build();

        return switch (provider.toLowerCase()) {
            case "google" -> exchangeGoogleCode(webClient, code);
            case "github" -> exchangeGitHubCode(webClient, code);
            case "facebook" -> exchangeFacebookCode(webClient, code);
            default -> Mono.error(new IllegalArgumentException("Unsupported provider: " + provider));
        };
    }

    private Mono<String> exchangeGoogleCode(WebClient webClient, String code) {
        return webClient.post()
                .uri("https://oauth2.googleapis.com/token")
                .bodyValue(Map.of(
                        "client_id", googleClientId,
                        "client_secret", googleClientSecret,
                        "code", code,
                        "grant_type", "authorization_code",
                        "redirect_uri", redirectUri + "/google"
                ))
                .retrieve()
                .bodyToMono(Map.class)
                .map(response -> (String) response.get("access_token"));
    }

    private Mono<String> exchangeGitHubCode(WebClient webClient, String code) {
        return webClient.post()
                .uri("https://github.com/login/oauth/access_token")
                .header("Accept", "application/json")
                .bodyValue(Map.of(
                        "client_id", githubClientId,
                        "client_secret", githubClientSecret,
                        "code", code
                ))
                .retrieve()
                .bodyToMono(Map.class)
                .map(response -> (String) response.get("access_token"));
    }

    private Mono<String> exchangeFacebookCode(WebClient webClient, String code) {
        // Facebook token exchange implementation
        return Mono.error(new UnsupportedOperationException("Facebook integration not yet implemented"));
    }

    private Mono<Map<String, Object>> getUserInfoFromProvider(String accessToken, String provider) {
        WebClient webClient = webClientBuilder.build();

        return switch (provider.toLowerCase()) {
            case "google" -> getGoogleUserInfo(webClient, accessToken);
            case "github" -> getGitHubUserInfo(webClient, accessToken);
            case "facebook" -> getFacebookUserInfo(webClient, accessToken);
            default -> Mono.error(new IllegalArgumentException("Unsupported provider: " + provider));
        };
    }

    private Mono<Map<String, Object>> getGoogleUserInfo(WebClient webClient, String accessToken) {
        return webClient.get()
                .uri("https://www.googleapis.com/oauth2/v2/userinfo")
                .header("Authorization", "Bearer " + accessToken)
                .retrieve()
                .bodyToMono(Map.class);
    }

    private Mono<Map<String, Object>> getGitHubUserInfo(WebClient webClient, String accessToken) {
        return webClient.get()
                .uri("https://api.github.com/user")
                .header("Authorization", "Bearer " + accessToken)
                .header("Accept", "application/vnd.github.v3+json")
                .retrieve()
                .bodyToMono(Map.class)
                .flatMap(userInfo -> {
                    // GitHub doesn't always return email in main API call
                    return webClient.get()
                            .uri("https://api.github.com/user/emails")
                            .header("Authorization", "Bearer " + accessToken)
                            .header("Accept", "application/vnd.github.v3+json")
                            .retrieve()
                            .bodyToMono(Object[].class)
                            .map(emails -> {
                                // Find primary email
                                for (Object emailObj : emails) {
                                    @SuppressWarnings("unchecked")
                                    Map<String, Object> emailMap = (Map<String, Object>) emailObj;
                                    if (Boolean.TRUE.equals(emailMap.get("primary"))) {
                                        userInfo.put("email", emailMap.get("email"));
                                        break;
                                    }
                                }
                                return userInfo;
                            });
                });
    }

    private Mono<Map<String, Object>> getFacebookUserInfo(WebClient webClient, String accessToken) {
        return webClient.get()
                .uri("https://graph.facebook.com/me?fields=id,name,email")
                .header("Authorization", "Bearer " + accessToken)
                .retrieve()
                .bodyToMono(Map.class);
    }

    private Mono<User> processUserInfo(Map<String, Object> userInfo, String provider) {
        String email = (String) userInfo.get("email");
        String name = (String) userInfo.get("name");
        String providerId = userInfo.get("id").toString();

        if (email == null || email.isEmpty()) {
            return Mono.error(new RuntimeException("Email not provided by " + provider));
        }

        return userRepository.findByEmail(email)
                .switchIfEmpty(createSocialUser(email, name, provider, providerId))
                .flatMap(user -> updateUserLastLogin(user, provider));
    }

    private Mono<User> createSocialUser(String email, String name, String provider, String providerId) {
        log.info("Creating new social user: {} from provider: {}", email, provider);

        User newUser = User.builder()
                .userId(UUID.randomUUID())
                .email(email)
                .username(generateUsernameFromEmail(email))
                .name(name != null ? name : "Social User")
                .orgId(1) // Default organization
                .departmentId(1) // Default department
                .userTypeId(2) // DEPT_USER
                .userStatusId(1) // ACTIVE
                .authTypeId(2) // OAUTH
                .emailVerified(true) // Social emails are pre-verified
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();

        return userRepository.save(newUser);
    }

    private Mono<User> updateUserLastLogin(User user, String provider) {
        return userRepository.updateLastLogin(user.getUserId(), LocalDateTime.now())
                .thenReturn(user)
                .doOnSuccess(updatedUser -> log.info("Updated last login for social user: {} via {}", user.getEmail(), provider));
    }

    private Mono<SocialLoginResponse> generateJwtTokens(User user) {
        return Mono.zip(
                jwtTokenProvider.generateToken(user.getUserId().toString()),
                jwtTokenProvider.generateRefreshToken(user.getUsername())
        ).map(tokens -> SocialLoginResponse.builder()
                .accessToken(tokens.getT1())
                .refreshToken(tokens.getT2())
                .tokenType("Bearer")
                .expiresIn(jwtTokenProvider.getExpirationTime())
                .user(buildUserInfo(user))
                .provider(user.getAuthTypeId() == 2 ? "oauth" : "password")
                .build());
    }

    private SocialLoginResponse.UserInfo buildUserInfo(User user) {
        return SocialLoginResponse.UserInfo.builder()
                .userId(user.getUserId().toString())
                .email(user.getEmail())
                .username(user.getUsername())
                .name(user.getName())
                .orgId(user.getOrgId())
                .departmentId(user.getDepartmentId())
                .userType(getUserTypeName(user.getUserTypeId()))
                .userStatus(getUserStatusName(user.getUserStatusId()))
                .authType("OAUTH")
                .build();
    }

    private String generateUsernameFromEmail(String email) {
        return email.split("@")[0].toLowerCase().replaceAll("[^a-zA-Z0-9]", "") +
                System.currentTimeMillis() % 1000;
    }

    private String generateState() {
        return UUID.randomUUID().toString();
    }

    // Helper methods for user type/status names
    private String getUserTypeName(Integer typeId) {
        return switch (typeId) {
            case 1 -> "GUEST_USER";
            case 2 -> "DEPT_USER";
            case 3 -> "MANAGER";
            case 5 -> "DEPT_HEAD";
            case 8 -> "ORG_ADMIN";
            case 10 -> "SUPER_ADMIN";
            default -> "UNKNOWN";
        };
    }

    private String getUserStatusName(Integer statusId) {
        return switch (statusId) {
            case 1 -> "ACTIVE";
            case 2 -> "INACTIVE";
            case 3 -> "PENDING";
            case 4 -> "SUSPENDED";
            case 5 -> "LOCKED";
            default -> "UNKNOWN";
        };
    }
}
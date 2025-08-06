package com.iam.auth.service;

import com.iam.auth.security.CustomOAuth2User;
import com.iam.common.model.User;
import com.iam.common.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class OAuth2UserService extends DefaultReactiveOAuth2UserService {

    private final UserRepository userRepository;

    @Override
    public Mono<OAuth2User> loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        return super.loadUser(userRequest)
                .flatMap(oAuth2User -> {
                    String registrationId = userRequest.getClientRegistration().getRegistrationId();
                    return processOAuth2User(registrationId, oAuth2User);
                });
    }

    private Mono<OAuth2User> processOAuth2User(String registrationId, OAuth2User oAuth2User) {
        log.info("Processing OAuth2 user from provider: {}", registrationId);

        String email = extractEmail(registrationId, oAuth2User);
        String name = extractName(registrationId, oAuth2User);
        String providerId = extractProviderId(registrationId, oAuth2User);

        return userRepository.findByEmail(email)
                .switchIfEmpty(createOAuth2User(email, name, registrationId, providerId))
                .flatMap(user -> updateLastLogin(user, registrationId))
                .map(user -> new CustomOAuth2User(oAuth2User, user))
                .cast(OAuth2User.class);
    }

    private Mono<User> createOAuth2User(String email, String name, String provider, String providerId) {
        log.info("Creating new OAuth2 user: {} from provider: {}", email, provider);

        String username = generateUsernameFromEmail(email);

        User newUser = User.builder()
                .userId(UUID.randomUUID())
                .email(email)
                .username(username)
                .name(name)
                .orgId(1) // Default organization
                .departmentId(1) // Default department
                .userTypeId(2) // DEPT_USER
                .userStatusId(1) // ACTIVE
                .authTypeId(getAuthTypeId(provider))
                .emailVerified(true) // OAuth2 emails are pre-verified
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();

        return userRepository.save(newUser)
                .doOnSuccess(user -> log.info("OAuth2 user created successfully: {}", user.getEmail()));
    }

    private Mono<User> updateLastLogin(User user, String provider) {
        return userRepository.updateLastLogin(user.getUserId(), LocalDateTime.now())
                .thenReturn(user);
    }

    private String extractEmail(String registrationId, OAuth2User oAuth2User) {
        return switch (registrationId.toLowerCase()) {
            case "google" -> (String) oAuth2User.getAttributes().get("email");
            case "github" -> (String) oAuth2User.getAttributes().get("email");
            case "facebook" -> (String) oAuth2User.getAttributes().get("email");
            default -> throw new IllegalArgumentException("Unsupported OAuth2 provider: " + registrationId);
        };
    }

    private String extractName(String registrationId, OAuth2User oAuth2User) {
        return switch (registrationId.toLowerCase()) {
            case "google" -> (String) oAuth2User.getAttributes().get("name");
            case "github" -> (String) oAuth2User.getAttributes().get("name");
            case "facebook" -> (String) oAuth2User.getAttributes().get("name");
            default -> "Unknown User";
        };
    }

    private String extractProviderId(String registrationId, OAuth2User oAuth2User) {
        return switch (registrationId.toLowerCase()) {
            case "google" -> (String) oAuth2User.getAttributes().get("sub");
            case "github" -> oAuth2User.getAttributes().get("id").toString();
            case "facebook" -> (String) oAuth2User.getAttributes().get("id");
            default -> null;
        };
    }

    private String generateUsernameFromEmail(String email) {
        return email.split("@")[0].toLowerCase().replaceAll("[^a-zA-Z0-9]", "");
    }

    private Integer getAuthTypeId(String provider) {
        return switch (provider.toLowerCase()) {
            case "google" -> 2; // OAUTH
            case "github" -> 2; // OAUTH
            case "facebook" -> 2; // OAUTH
            default -> 1; // PASSWORD
        };
    }
}
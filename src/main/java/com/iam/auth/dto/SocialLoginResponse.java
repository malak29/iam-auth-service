package com.iam.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SocialLoginResponse {
    private String accessToken;
    private String refreshToken;
    private String tokenType = "Bearer";
    private Long expiresIn;
    private UserInfo user;
    private String provider;
    private LocalDateTime loginAt;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class UserInfo {
        private String userId;
        private String email;
        private String username;
        private String name;
        private Integer orgId;
        private Integer departmentId;
        private String userType;
        private String userStatus;
        private String authType;
        private String profilePicture;
        private Boolean emailVerified;
    }
}
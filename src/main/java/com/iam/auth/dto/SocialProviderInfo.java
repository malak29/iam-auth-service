package com.iam.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SocialProviderInfo {
    private String name;
    private String providerId;
    private Boolean enabled;
    private String icon;
    private String authUrl;
    private String displayName;
    private String description;
}
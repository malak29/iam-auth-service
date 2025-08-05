package com.iam.auth.security;

import com.iam.common.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.*;

@RequiredArgsConstructor
public class CustomOAuth2User implements OAuth2User {

    private final OAuth2User oauth2User;
    private final User user;

    @Override
    public Map<String, Object> getAttributes() {
        Map<String, Object> attributes = new HashMap<>(oauth2User.getAttributes());
        // Add custom user attributes
        attributes.put("userId", user.getUserId().toString());
        attributes.put("userType", user.getUserTypeId());
        attributes.put("orgId", user.getOrgId());
        return attributes;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Set<GrantedAuthority> authorities = new HashSet<>(oauth2User.getAuthorities());
        // Add custom authorities based on user type
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));

        if (user.getUserTypeId() >= 8) {
            authorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
        }

        return authorities;
    }

    @Override
    public String getName() {
        return user.getEmail();
    }

    public User getUser() {
        return user;
    }
}
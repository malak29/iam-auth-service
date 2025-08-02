package com.iam.auth.service;

import com.iam.auth.dto.LoginResponse;
import com.iam.common.model.User;
import org.springframework.stereotype.Service;

@Service
public class AuthUtilityService {

    public LoginResponse.UserInfo buildUserInfo(User user) {
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

    public String getUserTypeName(Integer userTypeId) {
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

    public String getUserStatusName(Integer userStatusId) {
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
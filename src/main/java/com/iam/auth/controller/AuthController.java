package com.iam.auth.controller;

import com.iam.auth.config.ApiRoutes;
import com.iam.auth.dto.*;
import com.iam.auth.service.AuthService;
import com.iam.common.response.ApiResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(ApiRoutes.AUTH)
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = "*")
public class AuthController {

    private final AuthService authService;

    @PostMapping(ApiRoutes.LOGIN)
    public ResponseEntity<ApiResponse<LoginResponse>> login(@Valid @RequestBody LoginRequest loginRequest) {
        log.info("Login request received for email: {}", loginRequest.getEmail());

        LoginResponse loginResponse = authService.login(loginRequest);

        return ResponseEntity.ok(
                ApiResponse.success(loginResponse, "Login successful")
        );
    }

    @PostMapping(ApiRoutes.REFRESH)
    public ResponseEntity<ApiResponse<LoginResponse>> refreshToken(@Valid @RequestBody RefreshTokenRequest refreshRequest) {
        log.info("Token refresh request received");

        LoginResponse loginResponse = authService.refreshToken(refreshRequest);

        return ResponseEntity.ok(
                ApiResponse.success(loginResponse, "Token refreshed successfully")
        );
    }

    @PostMapping(ApiRoutes.LOGOUT)
    public ResponseEntity<ApiResponse<String>> logout(@Valid @RequestBody LogoutRequest logoutRequest) {
        log.info("Logout request received");

        ApiResponse<String> response = authService.logout(logoutRequest);

        return ResponseEntity.ok(response);
    }

    @GetMapping(ApiRoutes.HEALTH)
    public ResponseEntity<ApiResponse<String>> health() {
        return ResponseEntity.ok(
                ApiResponse.success("OK", "Auth service is running")
        );
    }

    @PostMapping(ApiRoutes.VALIDATE)
    public ResponseEntity<ApiResponse<String>> validateToken(@RequestHeader("Authorization") String authHeader) {
        log.info("Token validation request received");

        try {
            // Extract token from "Bearer <token>"
            if (!authHeader.startsWith("Bearer ")) {
                return ResponseEntity.badRequest().body(
                        ApiResponse.error("Invalid authorization header format")
                );
            }

            String token = authHeader.substring(7);
            // Add token validation logic here using JwtTokenProvider

            return ResponseEntity.ok(
                    ApiResponse.success("Valid", "Token is valid")
            );
        } catch (Exception e) {
            log.error("Token validation failed: {}", e.getMessage());
            return ResponseEntity.badRequest().body(
                    ApiResponse.error("Invalid token")
            );
        }
    }
}
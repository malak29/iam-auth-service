package com.iam.auth.controller;

import com.iam.auth.dto.*;
import com.iam.auth.service.AuthService;
import com.iam.common.response.ApiResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = "*")
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<LoginResponse>> login(@Valid @RequestBody LoginRequest loginRequest) {
        log.info("Login request received for email: {}", loginRequest.getEmail());

        LoginResponse loginResponse = authService.login(loginRequest);

        return ResponseEntity.ok(
                ApiResponse.success(loginResponse, "Login successful")
        );
    }

    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<LoginResponse>> refreshToken(@Valid @RequestBody RefreshTokenRequest refreshRequest) {
        log.info("Token refresh request received");

        LoginResponse loginResponse = authService.refreshToken(refreshRequest);

        return ResponseEntity.ok(
                ApiResponse.success(loginResponse, "Token refreshed successfully")
        );
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<String>> logout(@Valid @RequestBody LogoutRequest logoutRequest) {
        log.info("Logout request received");

        ApiResponse<String> response = authService.logout(logoutRequest);

        return ResponseEntity.ok(response);
    }

    @GetMapping("/health")
    public ResponseEntity<ApiResponse<String>> health() {
        return ResponseEntity.ok(
                ApiResponse.success("OK", "Auth service is running")
        );
    }
}
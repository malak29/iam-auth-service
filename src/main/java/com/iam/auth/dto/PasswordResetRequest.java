package com.iam.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class PasswordResetRequest {
    @Email(message = "Please provide a valid email address")
    @NotBlank(message = "Email is required")
    private String email;
}
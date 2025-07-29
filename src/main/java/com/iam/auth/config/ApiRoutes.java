package com.iam.auth.config;

public final class ApiRoutes {

    private ApiRoutes() {} // Prevent instantiation

    public static final String API_V1 = "/api/v1";

    // Auth base routes
    public static final String AUTH = API_V1 + "/auth";

    // Auth endpoints
    public static final String LOGIN = "/login";
    public static final String LOGOUT = "/logout";
    public static final String REFRESH = "/refresh";
    public static final String HEALTH = "/health";
    public static final String VALIDATE = "/validate";

    // Password management
    public static final String FORGOT_PASSWORD = "/forgot-password";
    public static final String RESET_PASSWORD = "/reset-password";
    public static final String CHANGE_PASSWORD = "/change-password";

    // Email verification
    public static final String VERIFY_EMAIL = "/verify-email";
    public static final String RESEND_VERIFICATION = "/resend-verification";

    // Social login (for future)
    public static final String GOOGLE_LOGIN = "/google";
    public static final String FACEBOOK_LOGIN = "/facebook";
    public static final String GITHUB_LOGIN = "/github";

    // Complete endpoint paths
    public static final String AUTH_LOGIN = AUTH + LOGIN;
    public static final String AUTH_LOGOUT = AUTH + LOGOUT;
    public static final String AUTH_REFRESH = AUTH + REFRESH;
    public static final String AUTH_HEALTH = AUTH + HEALTH;
    public static final String AUTH_VALIDATE = AUTH + VALIDATE;
    public static final String AUTH_FORGOT_PASSWORD = AUTH + FORGOT_PASSWORD;
    public static final String AUTH_RESET_PASSWORD = AUTH + RESET_PASSWORD;
    public static final String AUTH_CHANGE_PASSWORD = AUTH + CHANGE_PASSWORD;
    public static final String AUTH_VERIFY_EMAIL = AUTH + VERIFY_EMAIL;
    public static final String AUTH_RESEND_VERIFICATION = AUTH + RESEND_VERIFICATION;
}
package com.iam.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
@ComponentScan( basePackages = {
        "com.iam.auth",
        "com.iam.common"
})
public class AuthServiceApplication {
    public static void main (String[] args) {
        SpringApplication.run(AuthServiceApplication.class, args);
    }
}

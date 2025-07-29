package com.iam.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication
@ComponentScan( basePackages = {
        "com.iam.auth",
        "com.iam.common"
})
@EnableJpaRepositories(basePackages = "com.iam.common.repository")
@EntityScan(basePackages = {
        "com.iam.common.model"
})
public class AuthServiceApplication {
    public static void main (String[] args) {
        SpringApplication.run(AuthServiceApplication.class, args);
    }
}

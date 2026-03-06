package com.varutri.honeypot;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling // Enables scheduled tasks (rate limit cleanup)
public class VarutriHoneypotApplication {

    public static void main(String[] args) {
        SpringApplication.run(VarutriHoneypotApplication.class, args);
    }
}

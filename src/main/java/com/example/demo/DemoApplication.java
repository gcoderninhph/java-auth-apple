package com.example.demo;

import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@RestController
@RequestMapping("/api")
public class DemoApplication {

    private final LoginAppleService loginAppleService;

    public DemoApplication(LoginAppleService loginAppleService) {
        this.loginAppleService = loginAppleService;
    }

    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }

    @GetMapping("/login")
    public ResponseEntity<?> login(@RequestParam String token) throws InvalidJwtException, MalformedClaimException {
        loginAppleService.validateToken(token);
        return ResponseEntity.ok("done");
    }


}

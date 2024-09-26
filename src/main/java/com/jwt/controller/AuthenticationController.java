package com.jwt.controller;

import com.jwt.model.AuthenticationResponse;
import com.jwt.model.User;
import com.jwt.repository.UserRepository;
import com.jwt.service.AuthenticationService;
import com.jwt.service.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
public class AuthenticationController {

    private final AuthenticationService authService;

    public AuthenticationController(AuthenticationService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody User request){
        return ResponseEntity.ok(authService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(@RequestBody User request){
        return ResponseEntity.ok(authService.authenticate(request));
    }

    @PostMapping("/token-refresh")
    public ResponseEntity refreshToken(HttpServletRequest request,
                                                               HttpServletResponse response){
        return authService.refreshToken(request,response);
    }

    @GetMapping("/test")
    public String test(){
        log.info("TESTING LOG WITH @Slf4j......");
        return "TESTING";
    }

    @GetMapping("/admin-only")
    public ResponseEntity<String> adminOnly(){
        return ResponseEntity.ok("ADMIN ONLY");
    }
}

package com.SpringSecurity.SecurityDemo.controller;

import com.SpringSecurity.SecurityDemo.jwt.JwtUtils;
import com.SpringSecurity.SecurityDemo.dto.LoginRequest;
import com.SpringSecurity.SecurityDemo.dto.LoginResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
public class GreetingsController {

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private AuthenticationManager authenticationManager;

    @GetMapping("/hello")
    public String hello() {
        return "Hello";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public String helloAdmin() {
        return "Hello Admin";
    }

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {
        Authentication authentication;
        try {
            authentication = authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        } catch (AuthenticationException exception) {
            Map<String, Object> map = new HashMap<>();
            map.put("message", "Bad credentials");
            map.put("status", false);
            return new ResponseEntity<Object>(map, HttpStatus.NOT_FOUND);
        }

        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetails userDetails = (UserDetails)authentication.getPrincipal();

        String jwtToken = jwtUtils.generateTokenFromUsername(userDetails);

        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        LoginResponse loginResponse = new LoginResponse(userDetails.getUsername(),roles,jwtToken);
        return ResponseEntity.ok(loginResponse);
    }
}

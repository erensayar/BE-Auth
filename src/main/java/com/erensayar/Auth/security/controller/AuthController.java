package com.erensayar.Auth.security.controller;

import com.erensayar.Auth.security.model.entity.User;
import com.erensayar.Auth.security.model.enums.Role;
import com.erensayar.Auth.security.model.request.LoginRequest;
import com.erensayar.Auth.security.model.request.SignupRequest;
import com.erensayar.Auth.security.model.response.LoginResponse;
import com.erensayar.Auth.security.model.response.MessageResponse;
import com.erensayar.Auth.security.repository.UserRepository;
import com.erensayar.Auth.security.service.JwtTokenService;
import javax.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@CrossOrigin(origins = "*", maxAge = 3600)
@RequestMapping("/api/auth")
@RestController
public class AuthController {

  private final AuthenticationManager authenticationManager;
  private final UserRepository userRepository;
  private final PasswordEncoder passwordEncoder;
  private final JwtTokenService jwtTokenService;

  @PostMapping("/signin")
  public ResponseEntity<LoginResponse> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
    // TODO: Auth servise al burayı

    Authentication authentication = authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(
            loginRequest.getUsername(),
            loginRequest.getPassword()));

    SecurityContextHolder.getContext().setAuthentication(authentication);
    String jwtToken = jwtTokenService.generateJwtToken(authentication);

    User user = (User) authentication.getPrincipal();

    return ResponseEntity.ok(new LoginResponse(
        jwtToken,
        user.getId(),
        user.getUsername(),
        user.getEmail(),
        user.getRole()));
  }

  @PostMapping("/signup")
  public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
    if (userRepository.existsByUsername(signUpRequest.getUsername())) {
      return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already taken!"));
    }
    if (userRepository.existsByEmail(signUpRequest.getEmail())) {
      return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already in use!"));
    }

    userRepository.save(User.builder()
        .username(signUpRequest.getUsername())
        .email(signUpRequest.getEmail())
        .password(passwordEncoder.encode(signUpRequest.getPassword()))
        .role(signUpRequest.getRole() == null ? Role.USER : signUpRequest.getRole())
        .build());

    return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
  }
}



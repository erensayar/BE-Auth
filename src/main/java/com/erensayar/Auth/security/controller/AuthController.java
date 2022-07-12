package com.erensayar.Auth.security.controller;

import com.erensayar.Auth.security.model.request.LoginRequest;
import com.erensayar.Auth.security.model.request.SignupRequest;
import com.erensayar.Auth.security.model.response.LoginResponse;
import com.erensayar.Auth.security.model.response.MessageResponse;
import com.erensayar.Auth.security.service.AuthenticationService;
import javax.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
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

  private final AuthenticationService authenticationService;

  @PostMapping("/signin")
  public ResponseEntity<LoginResponse> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
    return ResponseEntity.ok(authenticationService.signIn(loginRequest));
  }

  @PostMapping("/signup")
  public ResponseEntity<MessageResponse> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
    return ResponseEntity.ok(authenticationService.signUp(signUpRequest));
  }
}

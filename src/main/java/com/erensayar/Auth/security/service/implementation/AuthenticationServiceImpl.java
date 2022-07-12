package com.erensayar.Auth.security.service.implementation;

import com.erensayar.Auth.security.model.entity.User;
import com.erensayar.Auth.security.model.enums.Role;
import com.erensayar.Auth.security.model.request.LoginRequest;
import com.erensayar.Auth.security.model.request.SignupRequest;
import com.erensayar.Auth.security.model.response.LoginResponse;
import com.erensayar.Auth.security.model.response.MessageResponse;
import com.erensayar.Auth.security.repository.UserRepository;
import com.erensayar.Auth.security.service.AuthenticationService;
import com.erensayar.Auth.security.service.util.JwtTokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
public class AuthenticationServiceImpl implements AuthenticationService {

  private final AuthenticationManager authenticationManager;
  private final UserRepository userRepository;
  private final PasswordEncoder passwordEncoder;
  private final JwtTokenService jwtTokenService;

  @Override
  public LoginResponse signIn(LoginRequest loginRequest) {
    Authentication authentication = authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(
            loginRequest.getUsername(),
            loginRequest.getPassword()));

    SecurityContextHolder.getContext().setAuthentication(authentication);
    String jwtToken = jwtTokenService.generateJwtToken(authentication);

    User user = (User) authentication.getPrincipal();

    return new LoginResponse(
        jwtToken,
        user.getId(),
        user.getUsername(),
        user.getEmail(),
        user.getRole());
  }

  @Override
  public MessageResponse signUp(SignupRequest signUpRequest) {
    if (userRepository.existsByUsername(signUpRequest.getUsername())) {
      return new MessageResponse("Error: Username is already taken!");
    }
    if (userRepository.existsByEmail(signUpRequest.getEmail())) {
      return new MessageResponse("Error: Email is already in use!");
    }
    userRepository.save(User.builder()
        .username(signUpRequest.getUsername())
        .email(signUpRequest.getEmail())
        .password(passwordEncoder.encode(signUpRequest.getPassword()))
        .role(signUpRequest.getRole() == null ? Role.USER : signUpRequest.getRole())
        .build());
    return new MessageResponse("User registered successfully!");
  }
}

package com.erensayar.Auth.security.service;

import com.erensayar.Auth.security.model.request.LoginRequest;
import com.erensayar.Auth.security.model.request.SignupRequest;
import com.erensayar.Auth.security.model.response.LoginResponse;
import com.erensayar.Auth.security.model.response.MessageResponse;

public interface AuthenticationService {

  LoginResponse signIn(LoginRequest loginRequest);

  MessageResponse signUp(SignupRequest signUpRequest);

}

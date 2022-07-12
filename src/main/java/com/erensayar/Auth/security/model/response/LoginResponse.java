package com.erensayar.Auth.security.model.response;

import com.erensayar.Auth.security.model.enums.Role;
import java.util.UUID;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class LoginResponse {
  private String type;
  private String token;
  private Long id;
  private String username;
  private String email;
  private Role role;

  public LoginResponse(String token, Long id, String username, String email, Role role) {
    this.type = "Bearer";
    this.token = token;
    this.id = id;
    this.username = username;
    this.email = email;
    this.role = role;
  }

}

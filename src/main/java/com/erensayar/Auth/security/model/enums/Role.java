package com.erensayar.Auth.security.model.enums;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum Role {
  UNKNOWN(0),
  ADMIN(1),
  USER(2);

  private final int val;

  public static Role getValById(Integer id) {
    for (Role e : values()) {
      if (e.val == id) {
        return e;
      }
    }
    return UNKNOWN;
  }

}

package com.erensayar.Auth.security.repository;

import com.erensayar.Auth.security.model.entity.User;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

  Optional<User> findByEmail(String email); // TODO: usernameden giriş değil de ail ile giris yapilacak

  Boolean existsByEmail(String email);

  Optional<User> findByUsername(String username);

  Boolean existsByUsername(String username);

}
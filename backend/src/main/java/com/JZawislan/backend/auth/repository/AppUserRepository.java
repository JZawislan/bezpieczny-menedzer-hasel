package com.JZawislan.backend.auth.repository;

import java.util.Optional;

import com.JZawislan.backend.auth.model.AppUser;
import com.JZawislan.backend.auth.model.UserRole;

import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

public interface AppUserRepository extends JpaRepository<AppUser, Long> {
	boolean existsByUsername(String username);

	boolean existsByEmail(String email);

	boolean existsByRole(UserRole role);

	Optional<AppUser> findByUsername(String username);
    Optional<AppUser> findByEmail(String email);

    @Transactional
    @Modifying
    @Query("update AppUser u set u.passwordHash = ?2 where u.email = ?1")
    void updatePassword(String email, String password);
}



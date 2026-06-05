package com.JZawislan.backend.auth.repository;

import java.util.Optional;

import com.JZawislan.backend.auth.model.AppUser;
import com.JZawislan.backend.auth.model.UserRole;

import org.springframework.data.jpa.repository.JpaRepository;

public interface AppUserRepository extends JpaRepository<AppUser, Long> {
	boolean existsByUsername(String username);

	boolean existsByRole(UserRole role);

	Optional<AppUser> findByUsername(String username);
}



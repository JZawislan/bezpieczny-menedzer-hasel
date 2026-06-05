package com.JZawislan.backend.auth;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

public interface AppUserRepository extends JpaRepository<AppUser, Long> {
	boolean existsByUsername(String username);

	boolean existsByRole(UserRole role);

	Optional<AppUser> findByUsername(String username);
}

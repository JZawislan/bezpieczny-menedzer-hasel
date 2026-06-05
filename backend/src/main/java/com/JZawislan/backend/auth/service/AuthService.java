package com.JZawislan.backend.auth.service;

import java.util.Map;

import com.JZawislan.backend.auth.dto.AuthRequest;
import com.JZawislan.backend.auth.dto.AuthResponse;
import com.JZawislan.backend.auth.dto.KdfResponse;
import com.JZawislan.backend.auth.dto.RegisterRequest;
import com.JZawislan.backend.auth.model.AppUser;
import com.JZawislan.backend.auth.model.UserRole;
import com.JZawislan.backend.auth.repository.AppUserRepository;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class AuthService {

	private final AppUserRepository users;
	private final PasswordEncoder passwordEncoder;
	private final JwtService jwtService;

	public AuthService(AppUserRepository users, PasswordEncoder passwordEncoder, JwtService jwtService) {
		this.users = users;
		this.passwordEncoder = passwordEncoder;
		this.jwtService = jwtService;
	}

	public AuthResponse register(RegisterRequest request) {
		String username = normalizeUsername(request.username());
		if (users.existsByUsername(username)) {
			throw new ResponseStatusException(HttpStatus.CONFLICT, "Username is already taken");
		}
		if (request.kdfIterations() < 100_000) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "KDF iterations are too low");
		}

		UserRole role = users.existsByRole(UserRole.ADMIN) ? UserRole.USER : UserRole.ADMIN;
		AppUser user = users.save(new AppUser(
				username,
				passwordEncoder.encode(request.password()),
				request.kdfSalt(),
				request.kdfIterations(),
				role));
		return toAuthResponse(user);
	}

	public KdfResponse kdf(String username) {
		AppUser user = users.findByUsername(normalizeUsername(username))
				.orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
		if (user.getKdfSalt() == null || user.getKdfSalt().isBlank() || user.getKdfIterations() == null
				|| user.getKdfIterations() < 100_000) {
			throw new ResponseStatusException(HttpStatus.CONFLICT, "User was created before vault encryption setup");
		}
		return new KdfResponse(user.getUsername(), user.getKdfSalt(), user.getKdfIterations());
	}

	public AuthResponse login(AuthRequest request) {
		String username = normalizeUsername(request.username());
		AppUser user = users.findByUsername(username)
				.orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials"));

		if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
			throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
		}

		return toAuthResponse(user);
	}

	public Map<String, String> me(Authentication authentication) {
		String role = authentication.getAuthorities().stream()
				.findFirst()
				.map(authority -> authority.getAuthority().replace("ROLE_", ""))
				.orElse(UserRole.USER.name());
		return Map.of("username", authentication.getName(), "role", role);
	}

	private AuthResponse toAuthResponse(AppUser user) {
		return new AuthResponse(jwtService.createToken(user.getUsername(), user.getRole()), user.getUsername(), user.getRole());
	}

	private String normalizeUsername(String username) {
		return username.trim().toLowerCase();
	}
}





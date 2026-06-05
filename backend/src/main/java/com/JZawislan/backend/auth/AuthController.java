package com.JZawislan.backend.auth;

import java.util.Map;

import jakarta.validation.Valid;

import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api")
public class AuthController {

	private final AppUserRepository users;
	private final PasswordEncoder passwordEncoder;
	private final JwtService jwtService;

	public AuthController(AppUserRepository users, PasswordEncoder passwordEncoder, JwtService jwtService) {
		this.users = users;
		this.passwordEncoder = passwordEncoder;
		this.jwtService = jwtService;
	}

	@PostMapping("/auth/register")
	@ResponseStatus(HttpStatus.CREATED)
	public AuthResponse register(@Valid @RequestBody RegisterRequest request) {
		String username = request.username().trim().toLowerCase();
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
		return new AuthResponse(jwtService.createToken(user.getUsername(), user.getRole()), user.getUsername(), user.getRole());
	}

	@GetMapping("/auth/kdf/{username}")
	public KdfResponse kdf(@PathVariable String username) {
		AppUser user = users.findByUsername(username.trim().toLowerCase())
				.orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
		if (user.getKdfSalt() == null || user.getKdfSalt().isBlank() || user.getKdfIterations() == null
				|| user.getKdfIterations() < 100_000) {
			throw new ResponseStatusException(HttpStatus.CONFLICT, "User was created before vault encryption setup");
		}
		return new KdfResponse(user.getUsername(), user.getKdfSalt(), user.getKdfIterations());
	}

	@PostMapping("/auth/login")
	public AuthResponse login(@Valid @RequestBody AuthRequest request) {
		String username = request.username().trim().toLowerCase();
		AppUser user = users.findByUsername(username)
				.orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials"));

		if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
			throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
		}

		return new AuthResponse(jwtService.createToken(user.getUsername(), user.getRole()), user.getUsername(), user.getRole());
	}

	@GetMapping("/me")
	public Map<String, String> me(org.springframework.security.core.Authentication authentication) {
		String role = authentication.getAuthorities().stream()
				.findFirst()
				.map(authority -> authority.getAuthority().replace("ROLE_", ""))
				.orElse(UserRole.USER.name());
		return Map.of("username", authentication.getName(), "role", role);
	}
}

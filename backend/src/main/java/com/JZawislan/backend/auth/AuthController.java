package com.JZawislan.backend.auth;

import java.util.Map;

import jakarta.validation.Valid;

import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
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
	public AuthResponse register(@Valid @RequestBody AuthRequest request) {
		String username = request.username().trim().toLowerCase();
		if (users.existsByUsername(username)) {
			throw new ResponseStatusException(HttpStatus.CONFLICT, "Username is already taken");
		}

		AppUser user = users.save(new AppUser(username, passwordEncoder.encode(request.password())));
		return new AuthResponse(jwtService.createToken(user.getUsername()), user.getUsername());
	}

	@PostMapping("/auth/login")
	public AuthResponse login(@Valid @RequestBody AuthRequest request) {
		String username = request.username().trim().toLowerCase();
		AppUser user = users.findByUsername(username)
				.orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials"));

		if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
			throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
		}

		return new AuthResponse(jwtService.createToken(user.getUsername()), user.getUsername());
	}

	@GetMapping("/me")
	public Map<String, String> me(org.springframework.security.core.Authentication authentication) {
		return Map.of("username", authentication.getName());
	}
}

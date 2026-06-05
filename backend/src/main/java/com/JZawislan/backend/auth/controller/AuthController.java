package com.JZawislan.backend.auth.controller;

import java.util.Map;

import jakarta.validation.Valid;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.JZawislan.backend.auth.dto.AuthRequest;
import com.JZawislan.backend.auth.dto.AuthResponse;
import com.JZawislan.backend.auth.dto.KdfResponse;
import com.JZawislan.backend.auth.dto.RegisterRequest;
import com.JZawislan.backend.auth.model.UserRole;
import com.JZawislan.backend.auth.service.AuthService;

@RestController
@RequestMapping("/api")
public class AuthController {

	private final AuthService authService;

	public AuthController(AuthService authService) {
		this.authService = authService;
	}

	@PostMapping("/auth/register")
	public AuthResponse register(@Valid @RequestBody RegisterRequest request) {
		return authService.register(request);
	}

	@GetMapping("/auth/kdf/{username}")
	public KdfResponse kdf(@PathVariable String username) {
		return authService.kdf(username);
	}

	@PostMapping("/auth/login")
	public AuthResponse login(@Valid @RequestBody AuthRequest request) {
		return authService.login(request);
	}

	@GetMapping("/me")
	public Map<String, String> me(Authentication authentication) {
		return authService.me(authentication);
	}
}






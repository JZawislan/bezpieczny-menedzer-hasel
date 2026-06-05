package com.JZawislan.backend.auth.service;

import java.util.Map;
import java.util.List;

import com.JZawislan.backend.auth.dto.AdminResetPasswordRequest;
import com.JZawislan.backend.auth.dto.AdminUserResponse;
import com.JZawislan.backend.auth.dto.AuthRequest;
import com.JZawislan.backend.auth.dto.AuthResponse;
import com.JZawislan.backend.auth.dto.ChangePasswordRequest;
import com.JZawislan.backend.auth.dto.KdfResponse;
import com.JZawislan.backend.auth.dto.RegisterRequest;
import com.JZawislan.backend.auth.model.AppUser;
import com.JZawislan.backend.auth.model.UserRole;
import com.JZawislan.backend.auth.repository.AppUserRepository;
import com.JZawislan.backend.vault.VaultEntryRepository;

import org.springframework.transaction.annotation.Transactional;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class AuthService {

	private final AppUserRepository users;
	private final VaultEntryRepository entries;
	private final PasswordEncoder passwordEncoder;
	private final JwtService jwtService;

	public AuthService(
			AppUserRepository users,
			VaultEntryRepository entries,
			PasswordEncoder passwordEncoder,
			JwtService jwtService) {
		this.users = users;
		this.entries = entries;
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

	@Transactional
	public AuthResponse changePassword(Authentication authentication, ChangePasswordRequest request) {
		validateKdfIterations(request.kdfIterations());
		AppUser user = users.findByUsername(authentication.getName())
				.orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

		if (!passwordEncoder.matches(request.currentPassword(), user.getPasswordHash())) {
			throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
		}

		user.resetPassword(passwordEncoder.encode(request.newPassword()), request.kdfSalt(), request.kdfIterations());
		return toAuthResponse(user);
	}

	public List<AdminUserResponse> adminUsers() {
		return users.findAll().stream()
				.map(this::toAdminUserResponse)
				.toList();
	}

	@Transactional
	public AdminUserResponse adminResetPassword(Long id, AdminResetPasswordRequest request) {
		validateKdfIterations(request.kdfIterations());
		AppUser user = users.findById(id)
				.orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
		entries.deleteAllByOwner(user);
		user.resetPassword(passwordEncoder.encode(request.password()), request.kdfSalt(), request.kdfIterations());
		return toAdminUserResponse(user);
	}

	@Transactional
	public void adminDeleteUser(Long id) {
		AppUser user = users.findById(id)
				.orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
		entries.deleteAllByOwner(user);
		users.delete(user);
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

	private AdminUserResponse toAdminUserResponse(AppUser user) {
		return new AdminUserResponse(
				user.getId(),
				user.getUsername(),
				user.getRole(),
				entries.countByOwnerUsername(user.getUsername()));
	}

	private void validateKdfIterations(int kdfIterations) {
		if (kdfIterations < 100_000) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "KDF iterations are too low");
		}
	}

	private String normalizeUsername(String username) {
		return username.trim().toLowerCase();
	}
}





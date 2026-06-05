package com.JZawislan.backend.auth.controller;

import java.util.List;

import jakarta.validation.Valid;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.JZawislan.backend.auth.dto.AdminResetPasswordRequest;
import com.JZawislan.backend.auth.dto.AdminUserResponse;
import com.JZawislan.backend.auth.service.AuthService;

@RestController
@RequestMapping("/api/admin/users")
public class AdminController {

	private final AuthService authService;

	public AdminController(AuthService authService) {
		this.authService = authService;
	}

	@GetMapping
	public List<AdminUserResponse> users() {
		return authService.adminUsers();
	}

	@PostMapping("/{id}/reset-password")
	public AdminUserResponse resetPassword(@PathVariable Long id, @Valid @RequestBody AdminResetPasswordRequest request) {
		return authService.adminResetPassword(id, request);
	}

	@DeleteMapping("/{id}")
	public void deleteUser(@PathVariable Long id) {
		authService.adminDeleteUser(id);
	}
}

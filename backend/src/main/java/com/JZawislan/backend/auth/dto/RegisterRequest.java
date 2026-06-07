package com.JZawislan.backend.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
		@NotBlank
		@Size(min = 3, max = 80)
		@Pattern(regexp = "^[a-zA-Z0-9._-]+$")
		String username,

		@NotBlank
		@Email
		@Size(max = 256)
		String email,

		@NotBlank
		@Size(min = 32, max = 256)
		String password,

		@NotBlank
		@Size(min = 16, max = 256)
		String kdfSalt,

		int kdfIterations) {
}


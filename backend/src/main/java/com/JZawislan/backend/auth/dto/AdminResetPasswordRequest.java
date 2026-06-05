package com.JZawislan.backend.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record AdminResetPasswordRequest(
		@NotBlank
		@Size(min = 32, max = 256)
		String password,

		@NotBlank
		@Size(min = 16, max = 256)
		String kdfSalt,

		int kdfIterations) {
}

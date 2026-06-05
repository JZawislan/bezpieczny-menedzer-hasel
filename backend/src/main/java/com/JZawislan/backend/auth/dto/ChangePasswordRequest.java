package com.JZawislan.backend.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ChangePasswordRequest(
		@NotBlank
		@Size(min = 32, max = 256)
		String currentPassword,

		@NotBlank
		@Size(min = 32, max = 256)
		String newPassword,

		@NotBlank
		@Size(min = 16, max = 256)
		String kdfSalt,

		int kdfIterations) {
}

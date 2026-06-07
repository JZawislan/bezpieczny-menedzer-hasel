package com.JZawislan.backend.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ForgotPasswordResetRequest(
		Integer otp,

		@NotBlank
		@Size(min = 32, max = 256)
		String password,

		@NotBlank
		@Size(min = 32, max = 256)
		String repeatPassword,

		@NotBlank
		@Size(min = 16, max = 256)
		String kdfSalt,

		int kdfIterations) {
}

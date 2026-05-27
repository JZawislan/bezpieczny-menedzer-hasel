package com.JZawislan.backend.auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record AuthRequest(
		@NotBlank
		@Size(min = 3, max = 80)
		@Pattern(regexp = "^[a-zA-Z0-9._-]+$")
		String username,

		@NotBlank
		@Size(min = 8, max = 120)
		String password) {
}

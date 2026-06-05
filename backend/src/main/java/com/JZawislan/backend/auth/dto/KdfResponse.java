package com.JZawislan.backend.auth.dto;

public record KdfResponse(
		String username,
		String kdfSalt,
		int kdfIterations) {
}


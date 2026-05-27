package com.JZawislan.backend.auth;

public record KdfResponse(
		String username,
		String kdfSalt,
		int kdfIterations) {
}

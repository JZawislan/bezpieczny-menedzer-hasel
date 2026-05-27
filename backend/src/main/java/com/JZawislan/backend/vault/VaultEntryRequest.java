package com.JZawislan.backend.vault;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record VaultEntryRequest(
		@NotBlank
		@Size(max = 120)
		String label,

		@NotBlank
		@Size(max = 10000)
		String encryptedPayload,

		@NotBlank
		@Size(max = 64)
		String iv,

		@NotBlank
		@Size(max = 40)
		String algorithm,

		@NotBlank
		@Size(max = 40)
		String kdf,

		int kdfIterations) {
}

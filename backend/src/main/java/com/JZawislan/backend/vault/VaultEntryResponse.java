package com.JZawislan.backend.vault;

import java.time.Instant;

public record VaultEntryResponse(
		Long id,
		String label,
		String encryptedPayload,
		String iv,
		String algorithm,
		String kdf,
		int kdfIterations,
		Instant createdAt,
		Instant updatedAt) {

	public static VaultEntryResponse from(VaultEntry entry) {
		return new VaultEntryResponse(
				entry.getId(),
				entry.getLabel(),
				entry.getEncryptedPayload(),
				entry.getIv(),
				entry.getAlgorithm(),
				entry.getKdf(),
				entry.getKdfIterations(),
				entry.getCreatedAt(),
				entry.getUpdatedAt());
	}
}

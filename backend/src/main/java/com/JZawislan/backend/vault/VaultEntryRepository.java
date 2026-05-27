package com.JZawislan.backend.vault;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

public interface VaultEntryRepository extends JpaRepository<VaultEntry, Long> {
	List<VaultEntry> findAllByOwnerUsernameOrderByUpdatedAtDesc(String username);

	Optional<VaultEntry> findByIdAndOwnerUsername(Long id, String username);
}

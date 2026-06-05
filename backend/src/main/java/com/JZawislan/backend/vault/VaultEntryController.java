package com.JZawislan.backend.vault;

import java.util.List;

import com.JZawislan.backend.auth.model.AppUser;
import com.JZawislan.backend.auth.repository.AppUserRepository;

import jakarta.validation.Valid;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/vault")
public class VaultEntryController {

	private final VaultEntryRepository entries;
	private final AppUserRepository users;

	public VaultEntryController(VaultEntryRepository entries, AppUserRepository users) {
		this.entries = entries;
		this.users = users;
	}

	@GetMapping
	public List<VaultEntryResponse> list(Authentication authentication) {
		return entries.findAllByOwnerUsernameOrderByUpdatedAtDesc(authentication.getName()).stream()
				.map(VaultEntryResponse::from)
				.toList();
	}

	@PostMapping
	@ResponseStatus(HttpStatus.CREATED)
	public VaultEntryResponse create(Authentication authentication, @Valid @RequestBody VaultEntryRequest request) {
		AppUser owner = users.findByUsername(authentication.getName())
				.orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid user"));

		return VaultEntryResponse.from(entries.save(new VaultEntry(
				owner,
				request.label().trim(),
				request.encryptedPayload(),
				request.iv(),
				request.algorithm(),
				request.kdf(),
				request.kdfIterations())));
	}

	@PutMapping("/{id}")
	public VaultEntryResponse update(Authentication authentication, @PathVariable Long id,
			@Valid @RequestBody VaultEntryRequest request) {
		VaultEntry entry = entries.findByIdAndOwnerUsername(id, authentication.getName())
				.orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Vault entry not found"));

		entry.update(
				request.label().trim(),
				request.encryptedPayload(),
				request.iv(),
				request.algorithm(),
				request.kdf(),
				request.kdfIterations());

		return VaultEntryResponse.from(entries.save(entry));
	}

	@DeleteMapping("/{id}")
	@ResponseStatus(HttpStatus.NO_CONTENT)
	public void delete(Authentication authentication, @PathVariable Long id) {
		VaultEntry entry = entries.findByIdAndOwnerUsername(id, authentication.getName())
				.orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Vault entry not found"));
		entries.delete(entry);
	}
}

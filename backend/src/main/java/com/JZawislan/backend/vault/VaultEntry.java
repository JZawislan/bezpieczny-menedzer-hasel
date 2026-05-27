package com.JZawislan.backend.vault;

import java.time.Instant;

import com.JZawislan.backend.auth.AppUser;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;

@Entity
@Table(name = "vault_entries", uniqueConstraints = {
		@UniqueConstraint(columnNames = { "owner_id", "id" })
})
public class VaultEntry {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@ManyToOne(fetch = FetchType.LAZY, optional = false)
	private AppUser owner;

	@Column(nullable = false, length = 120)
	private String label;

	@Column(nullable = false, columnDefinition = "text")
	private String encryptedPayload;

	@Column(nullable = false, length = 64)
	private String iv;

	@Column(nullable = false, length = 40)
	private String algorithm;

	@Column(nullable = false, length = 40)
	private String kdf;

	@Column(nullable = false)
	private int kdfIterations;

	@Column(nullable = false, updatable = false)
	private Instant createdAt;

	@Column(nullable = false)
	private Instant updatedAt;

	protected VaultEntry() {
	}

	public VaultEntry(AppUser owner, String label, String encryptedPayload, String iv, String algorithm, String kdf,
			int kdfIterations) {
		this.owner = owner;
		this.label = label;
		this.encryptedPayload = encryptedPayload;
		this.iv = iv;
		this.algorithm = algorithm;
		this.kdf = kdf;
		this.kdfIterations = kdfIterations;
	}

	@PrePersist
	void onCreate() {
		Instant now = Instant.now();
		createdAt = now;
		updatedAt = now;
	}

	@PreUpdate
	void onUpdate() {
		updatedAt = Instant.now();
	}

	public Long getId() {
		return id;
	}

	public String getLabel() {
		return label;
	}

	public String getEncryptedPayload() {
		return encryptedPayload;
	}

	public String getIv() {
		return iv;
	}

	public String getAlgorithm() {
		return algorithm;
	}

	public String getKdf() {
		return kdf;
	}

	public int getKdfIterations() {
		return kdfIterations;
	}

	public Instant getCreatedAt() {
		return createdAt;
	}

	public Instant getUpdatedAt() {
		return updatedAt;
	}

	public void update(String label, String encryptedPayload, String iv, String algorithm, String kdf, int kdfIterations) {
		this.label = label;
		this.encryptedPayload = encryptedPayload;
		this.iv = iv;
		this.algorithm = algorithm;
		this.kdf = kdf;
		this.kdfIterations = kdfIterations;
	}
}

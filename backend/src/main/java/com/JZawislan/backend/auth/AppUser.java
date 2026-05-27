package com.JZawislan.backend.auth;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "app_users")
public class AppUser {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Column(nullable = false, unique = true, length = 80)
	private String username;

	@Column(nullable = false)
	private String passwordHash;

	@Column(length = 256)
	private String kdfSalt;

	private Integer kdfIterations;

	protected AppUser() {
	}

	public AppUser(String username, String passwordHash) {
		this.username = username;
		this.passwordHash = passwordHash;
		this.kdfSalt = "";
		this.kdfIterations = 0;
	}

	public AppUser(String username, String passwordHash, String kdfSalt, int kdfIterations) {
		this.username = username;
		this.passwordHash = passwordHash;
		this.kdfSalt = kdfSalt;
		this.kdfIterations = kdfIterations;
	}

	public Long getId() {
		return id;
	}

	public String getUsername() {
		return username;
	}

	public String getPasswordHash() {
		return passwordHash;
	}

	public String getKdfSalt() {
		return kdfSalt;
	}

	public Integer getKdfIterations() {
		return kdfIterations;
	}
}

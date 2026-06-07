package com.JZawislan.backend.auth.model;

import jakarta.persistence.*;

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

    //TODO
    @Column(length = 256)
    private String email;

	@Enumerated(EnumType.STRING)
	@Column(length = 20)
	private UserRole role = UserRole.USER;

    @OneToOne(mappedBy = "appUser")
    private ForgotPassword forgotPassword;

	protected AppUser() {
	}

	public AppUser(String username, String passwordHash) {
		this.username = username;
		this.passwordHash = passwordHash;
		this.kdfSalt = "";
		this.kdfIterations = 0;
		this.role = UserRole.USER;
	}

	public AppUser(String username, String passwordHash, String kdfSalt, int kdfIterations) {
		this(username, passwordHash, kdfSalt, kdfIterations, UserRole.USER);
	}

	public AppUser(String username, String passwordHash, String kdfSalt, int kdfIterations, UserRole role) {
		this.username = username;
		this.passwordHash = passwordHash;
		this.kdfSalt = kdfSalt;
		this.kdfIterations = kdfIterations;
		this.role = role;
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

	public UserRole getRole() {
		return role == null ? UserRole.USER : role;
	}

	public void resetPassword(String passwordHash, String kdfSalt, int kdfIterations) {
		this.passwordHash = passwordHash;
		this.kdfSalt = kdfSalt;
		this.kdfIterations = kdfIterations;
	}
}


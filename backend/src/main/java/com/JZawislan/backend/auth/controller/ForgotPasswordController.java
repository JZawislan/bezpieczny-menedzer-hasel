package com.JZawislan.backend.auth.controller;

import com.JZawislan.backend.auth.dto.ForgotPasswordResetRequest;
import com.JZawislan.backend.auth.dto.MailBody;
import com.JZawislan.backend.auth.model.AppUser;
import com.JZawislan.backend.auth.model.ForgotPassword;
import com.JZawislan.backend.auth.repository.AppUserRepository;
import com.JZawislan.backend.auth.repository.ForgotPasswordRepository;
import com.JZawislan.backend.auth.service.EmailService;
import com.JZawislan.backend.vault.VaultEntryRepository;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.Date;
import java.util.Objects;
import java.util.Random;

@RestController
@RequestMapping("/api/auth/forgot-password")
public class ForgotPasswordController {

	private final AppUserRepository userRepository;
	private final EmailService emailService;
	private final ForgotPasswordRepository forgotPasswordRepository;
	private final PasswordEncoder passwordEncoder;
	private final VaultEntryRepository vaultEntryRepository;

	public ForgotPasswordController(
			AppUserRepository userRepository,
			EmailService emailService,
			ForgotPasswordRepository forgotPasswordRepository,
			PasswordEncoder passwordEncoder,
			VaultEntryRepository vaultEntryRepository) {
		this.userRepository = userRepository;
		this.emailService = emailService;
		this.forgotPasswordRepository = forgotPasswordRepository;
		this.passwordEncoder = passwordEncoder;
		this.vaultEntryRepository = vaultEntryRepository;
	}

	@PostMapping("/verifyMail/{email}")
	@Transactional
	public ResponseEntity<String> verifyEmail(@PathVariable String email) {
		String normalizedEmail = normalizeEmail(email);
		AppUser user = userRepository.findByEmail(normalizedEmail)
				.orElseThrow(() -> new UsernameNotFoundException("Wprowadz poprawny adres e-mail"));

		int otp = otpGenerator();
		MailBody mailBody = MailBody.builder()
				.to(normalizedEmail)
				.text("Kod do zresetowania hasla: " + otp + "\nKod jest wazny przez 15 minut.")
				.subject("Resetowanie hasla - BSK Menedzer")
				.build();

		forgotPasswordRepository.deleteAllByAppUser(user);
		forgotPasswordRepository.save(ForgotPassword.builder()
				.otp(otp)
				.expiration(new Date(System.currentTimeMillis() + 15 * 60 * 1000))
				.appUser(user)
				.build());
		emailService.sendSimpleMessage(mailBody);

		return ResponseEntity.ok("Email zostal wyslany do weryfikacji");
	}

	@PostMapping("/verifyOtp/{otp}/{email}")
	public ResponseEntity<String> verifyOtp(@PathVariable Integer otp, @PathVariable String email) {
		AppUser user = userRepository.findByEmail(normalizeEmail(email))
				.orElseThrow(() -> new UsernameNotFoundException("Wprowadz poprawny adres e-mail"));
		ForgotPassword forgotPassword = findValidOtp(otp, user);
		if (forgotPassword == null) {
			return new ResponseEntity<>("OTP wygaslo!", HttpStatus.EXPECTATION_FAILED);
		}

		return ResponseEntity.ok("OTP jest poprawny. Mozesz teraz zresetowac swoje haslo.");
	}

	@PostMapping("/changePassword")
	@Transactional
	public ResponseEntity<String> changePasswordHandler(
			@Valid @RequestBody ForgotPasswordResetRequest request) {
		if (!Objects.equals(request.password(), request.repeatPassword())) {
			return new ResponseEntity<>("Hasla nie sa takie same!", HttpStatus.BAD_REQUEST);
		}
		if (request.otp() == null) {
			return new ResponseEntity<>("Kod OTP jest wymagany.", HttpStatus.BAD_REQUEST);
		}
		if (request.kdfIterations() < 100_000) {
			return new ResponseEntity<>("Liczba iteracji KDF jest zbyt niska.", HttpStatus.BAD_REQUEST);
		}

		AppUser user = userRepository.findByEmail(normalizeEmail(request.email()))
				.orElseThrow(() -> new UsernameNotFoundException("Wprowadz poprawny adres e-mail"));
		ForgotPassword forgotPassword = findValidOtp(request.otp(), user);
		if (forgotPassword == null) {
			return new ResponseEntity<>("OTP wygaslo!", HttpStatus.EXPECTATION_FAILED);
		}
		if (user.getForgotPassword() != null) {
			user.setForgotPassword(null);
		}

		vaultEntryRepository.deleteAllByOwner(user);
		user.resetPassword(passwordEncoder.encode(request.password()), request.kdfSalt(), request.kdfIterations());
		userRepository.save(user);
		forgotPasswordRepository.delete(forgotPassword);

		return ResponseEntity.ok("Haslo zostalo zresetowane. Sejf zostal wyczyszczony, bo starego klucza nie da sie odzyskac.");
	}

	private ForgotPassword findValidOtp(Integer otp, AppUser user) {
		ForgotPassword forgotPassword = forgotPasswordRepository.findByOtpAndAppUser(otp, user)
				.orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Nieprawidlowy kod OTP."));
		if (forgotPassword.getExpiration().before(Date.from(Instant.now()))) {
			forgotPasswordRepository.deleteById(forgotPassword.getFpid());
			return null;
		}
		return forgotPassword;
	}

	private Integer otpGenerator() {
		Random random = new Random();
		return random.nextInt(100_000, 999_999);
	}

	private String normalizeEmail(String email) {
		return email.trim().toLowerCase();
	}
}
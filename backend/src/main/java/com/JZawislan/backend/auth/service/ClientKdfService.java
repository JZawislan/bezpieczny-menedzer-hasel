package com.JZawislan.backend.auth.service;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.springframework.stereotype.Service;

@Service
public class ClientKdfService {

	public static final int KDF_ITERATIONS = 210_000;

	private static final String AUTH_PURPOSE = "bezpieczny-menedzer:auth";
	private static final SecureRandom SECURE_RANDOM = new SecureRandom();

	public String generateSalt() {
		byte[] salt = new byte[16];
		SECURE_RANDOM.nextBytes(salt);
		return Base64.getEncoder().encodeToString(salt);
	}

	public String deriveAuthHash(String masterPassword, String saltBase64, int iterations) {
		try {
			byte[] salt = join(Base64.getDecoder().decode(saltBase64), AUTH_PURPOSE.getBytes(StandardCharsets.UTF_8));
			KeySpec spec = new PBEKeySpec(masterPassword.toCharArray(), salt, iterations, 256);
			byte[] hash = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
			return Base64.getEncoder().encodeToString(hash);
		} catch (Exception exception) {
			throw new IllegalStateException("Could not derive client auth hash", exception);
		}
	}

	private byte[] join(byte[] left, byte[] right) {
		byte[] result = new byte[left.length + right.length];
		System.arraycopy(left, 0, result, 0, left.length);
		System.arraycopy(right, 0, result, left.length, right.length);
		return result;
	}
}


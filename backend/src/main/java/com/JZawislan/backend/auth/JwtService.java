package com.JZawislan.backend.auth;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class JwtService {

	private static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9._-]+$");

	private final String secret;
	private final long expirationSeconds;

	public JwtService(
			@Value("${app.jwt.secret}") String secret,
			@Value("${app.jwt.expiration-seconds:3600}") long expirationSeconds) {
		if (secret.getBytes(StandardCharsets.UTF_8).length < 32) {
			throw new IllegalStateException("JWT secret must have at least 32 bytes for HS256");
		}
		this.secret = secret;
		this.expirationSeconds = expirationSeconds;
	}

	public String createToken(String username) {
		try {
			Instant now = Instant.now();
			JWTClaimsSet claims = new JWTClaimsSet.Builder()
					.subject(username)
					.issueTime(Date.from(now))
					.expirationTime(Date.from(now.plusSeconds(expirationSeconds)))
					.build();

			SignedJWT signedJwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);
			signedJwt.sign(new MACSigner(secret.getBytes(StandardCharsets.UTF_8)));
			return signedJwt.serialize();
		} catch (Exception exception) {
			throw new IllegalStateException("Could not create JWT token", exception);
		}
	}

	public String validateAndGetUsername(String token) {
		try {
			SignedJWT signedJwt = SignedJWT.parse(token);
			if (!signedJwt.verify(new MACVerifier(secret.getBytes(StandardCharsets.UTF_8)))) {
				return null;
			}

			JWTClaimsSet claims = signedJwt.getJWTClaimsSet();
			Date expirationTime = claims.getExpirationTime();
			String username = claims.getSubject();

			if (expirationTime == null || expirationTime.before(new Date())) {
				return null;
			}

			if (username == null) {
				return null;
			}

			Matcher usernameMatcher = USERNAME_PATTERN.matcher(username);
			if (!usernameMatcher.matches()) {
				return null;
			}

			return username;
		} catch (Exception exception) {
			return null;
		}
	}
}

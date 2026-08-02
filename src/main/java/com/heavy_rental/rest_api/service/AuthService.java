package com.heavy_rental.rest_api.service;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import com.heavy_rental.rest_api.security.JwtService;

@Service
public class AuthService {

	private static final String BASIC_PREFIX = "Basic ";

	private final AuthenticationManager authenticationManager;
	private final JwtService jwtService;

	public AuthService(AuthenticationManager authenticationManager, JwtService jwtService) {
		this.authenticationManager = authenticationManager;
		this.jwtService = jwtService;
	}

	/**
	 * Issue a JWT access token using HTTP Basic credentials.
	 * Returns only the raw token string (no {@code Bearer} prefix).
	 *
	 * @param authorizationHeader full {@code Authorization} header value, e.g. {@code Basic dXNlcjpwYXNz}
	 */
	public String getBearerToken(String authorizationHeader) {
		String[] credentials = parseBasicCredentials(authorizationHeader);
		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(credentials[0], credentials[1]));
		Jwt jwt = jwtService.generateToken(authentication);
		return jwt.getTokenValue();
	}

	/**
	 * @return {@code [username, password]}
	 */
	private static String[] parseBasicCredentials(String authorizationHeader) {
		if (authorizationHeader == null || authorizationHeader.isBlank()) {
			throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Basic authentication required");
		}
		if (!authorizationHeader.regionMatches(true, 0, BASIC_PREFIX, 0, BASIC_PREFIX.length())) {
			throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Basic authentication required");
		}

		String encoded = authorizationHeader.substring(BASIC_PREFIX.length()).trim();
		if (encoded.isEmpty()) {
			throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Basic authentication required");
		}

		final String decoded;
		try {
			decoded = new String(Base64.getDecoder().decode(encoded), StandardCharsets.UTF_8);
		}
		catch (IllegalArgumentException ex) {
			throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid Basic authentication encoding");
		}

		int colon = decoded.indexOf(':');
		if (colon < 0) {
			throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid Basic authentication credentials");
		}

		String username = decoded.substring(0, colon).trim();
		String password = decoded.substring(colon + 1);
		if (username.isBlank() || password.isBlank()) {
			throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Username and password are required");
		}
		return new String[] { username, password };
	}
}

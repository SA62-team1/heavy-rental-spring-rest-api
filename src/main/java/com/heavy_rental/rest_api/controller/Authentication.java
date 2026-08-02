package com.heavy_rental.rest_api.controller;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.heavy_rental.rest_api.service.AuthService;

/**
 * JWT authentication REST endpoints.
 *
 * <ul>
 *   <li>{@code GET /api/auth/getBearerToken} — HTTP Basic credentials → raw JWT only</li>
 * </ul>
 */
@RestController
@RequestMapping("/api/auth")
public class Authentication {

	private final AuthService authService;

	public Authentication(AuthService authService) {
		this.authService = authService;
	}

	/**
	 * Authenticate with HTTP Basic credentials and return only the raw JWT access token
	 * (plain text, no JSON wrapper, no {@code Bearer} prefix).
	 *
	 * <pre>
	 * GET /api/auth/getBearerToken
	 * Authorization: Basic base64(username:password)
	 * </pre>
	 */
	@GetMapping(value = "/getBearerToken", produces = MediaType.TEXT_PLAIN_VALUE)
	public ResponseEntity<String> getBearerToken(
			@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
		return ResponseEntity.ok()
				.contentType(MediaType.TEXT_PLAIN)
				.body(authService.getBearerToken(authorization));
	}
}

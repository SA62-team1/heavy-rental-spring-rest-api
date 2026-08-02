package com.heavy_rental.rest_api.controller;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.UUID;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.heavy_rental.rest_api.entity.User;
import com.heavy_rental.rest_api.repository.UserRepository;
import com.heavy_rental.rest_api.security.JwtService;

@SpringBootTest
@AutoConfigureMockMvc
class AuthenticationIntegrationTest {

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Autowired
	private JwtDecoder jwtDecoder;

	private String username;
	private String password;

	@BeforeEach
	void createUser() {
		username = "token_" + UUID.randomUUID().toString().substring(0, 8);
		password = "password123";
		userRepository.save(User.builder()
				.username(username)
				.password(passwordEncoder.encode(password))
				.email(username + "@example.com")
				.role("ROLE_USER")
				.enabled(true)
				.build());
	}

	@Test
	void getBearerTokenReturnsPlainTokenThatDecodes() throws Exception {
		MvcResult tokenResult = mockMvc.perform(get("/api/auth/getBearerToken")
						.header(HttpHeaders.AUTHORIZATION, basicAuth(username, password)))
				.andExpect(status().isOk())
				.andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_PLAIN))
				.andReturn();

		String token = tokenResult.getResponse().getContentAsString();
		Assertions.assertFalse(token.isBlank());
		Assertions.assertFalse(token.startsWith("Bearer "));
		Assertions.assertFalse(token.startsWith("{"));

		Jwt jwt = jwtDecoder.decode(token);
		Assertions.assertEquals(username, jwt.getSubject());
		Assertions.assertTrue(JwtService.rolesFrom(jwt).contains("ROLE_USER"));
		Assertions.assertNotNull(jwt.getId());
		Assertions.assertNotNull(jwt.getExpiresAt());
	}

	@Test
	void getBearerTokenWithBadPasswordReturns401() throws Exception {
		mockMvc.perform(get("/api/auth/getBearerToken")
						.header(HttpHeaders.AUTHORIZATION, basicAuth(username, "definitely-wrong")))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.error").value("invalid_credentials"));
	}

	@Test
	void getBearerTokenWithoutAuthReturns401() throws Exception {
		mockMvc.perform(get("/api/auth/getBearerToken"))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.error").value("unauthorized"));
	}

	@Test
	void protectedEndpointWithoutTokenReturns401() throws Exception {
		// No remaining auth "user" endpoint; actuator health is public.
		// A non-public path without a mapping still goes through security for authenticated routes
		// when matched; use a known protected path that has no handler → still requires auth first.
		mockMvc.perform(get("/api/auth/user"))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.error").value("unauthorized"));
	}

	private static String basicAuth(String username, String password) {
		String raw = username + ":" + password;
		return "Basic " + Base64.getEncoder().encodeToString(raw.getBytes(StandardCharsets.UTF_8));
	}
}

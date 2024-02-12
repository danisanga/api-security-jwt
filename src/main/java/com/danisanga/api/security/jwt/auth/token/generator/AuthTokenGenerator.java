package com.danisanga.api.security.jwt.auth.token.generator;

import com.danisanga.api.security.jwt.models.User;

/**
 * Generic authentication token generator interface.
 */
public interface AuthTokenGenerator {

    String generateToken(final User user);
}

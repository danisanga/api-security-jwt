package com.danisanga.api.security.jwt.auth.token.generator;

import com.danisanga.api.security.jwt.models.UserModel;

/**
 * Generic authentication token generator interface.
 */
public interface AuthTokenGenerator {

    String generateToken(final UserModel userModel);
}

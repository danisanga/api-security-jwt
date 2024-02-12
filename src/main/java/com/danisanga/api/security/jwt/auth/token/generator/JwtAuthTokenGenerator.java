package com.danisanga.api.security.jwt.auth.token.generator;

import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;

import javax.naming.AuthenticationException;

/**
 * JWT authentication token generator interface.
 */
public interface JwtAuthTokenGenerator extends AuthTokenGenerator {

    String resolveToken(final HttpServletRequest httpServletRequest);
    Claims resolveClaims(final HttpServletRequest httpServletRequest);
    boolean areClaimsValid(Claims claims) throws AuthenticationException;
}

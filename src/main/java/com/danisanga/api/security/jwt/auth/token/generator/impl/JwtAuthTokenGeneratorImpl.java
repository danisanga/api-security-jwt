package com.danisanga.api.security.jwt.auth.token.generator.impl;

import com.danisanga.api.security.jwt.auth.token.generator.JwtAuthTokenGenerator;
import com.danisanga.api.security.jwt.models.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.naming.AuthenticationException;
import java.util.Date;
import java.util.concurrent.TimeUnit;

/**
 * JWT authentication token generator class.
 * <br/>
 * Main responsibilities of this class are:
 *  <ul>
 *      <li> Generate new tokens. </li>
 *      <li> Validates authentication tokens. </li>
 *  </ul>
 */
@Component
public class JwtAuthTokenGeneratorImpl implements JwtAuthTokenGenerator {
    private static final SecretKey KEY = Jwts.SIG.HS256.key().build();

    private static final long ACCESS_TOKEN_VALIDITY = 60*60*1_000L;
    private static final String TOKEN_HEADER = "Authorization";
    private static final String TOKEN_PREFIX = "Bearer ";


    private final JwtParser jwtParser;

    /**
     * Default constructor.
     */
    public JwtAuthTokenGeneratorImpl(){
        this.jwtParser = Jwts.parser().verifyWith(KEY).build();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String generateToken(User user) {
        final Claims claims = Jwts.claims().subject(user.getEmail()).build();
        final Date tokenCreateTime = new Date();
        final Date tokenValidity = getTokenValidityDate(tokenCreateTime);
        return Jwts.builder()
                .claims(claims)
                .expiration(tokenValidity)
                .signWith(KEY)
                .compact();
    }

    /**
     * {@inheritDoc}
     */
    public Claims resolveClaims(final HttpServletRequest httpServletRequest) {
        try {
            final String token = resolveToken(httpServletRequest);
            if (token == null) {
                httpServletRequest.setAttribute("Bearer token is null", "Bearer token cannot be null for authentication");
            }
            return parseJwtClaims(token);
        } catch (ExpiredJwtException ex) {
            httpServletRequest.setAttribute("Expired Bearer token", ex.getMessage());
            throw ex;
        } catch (Exception ex) {
            httpServletRequest.setAttribute("Invalid Bearer token ", ex.getMessage());
            throw ex;
        }
    }

    /**
     * {@inheritDoc}
     */
    public String resolveToken(HttpServletRequest httpServletRequest) {

        final String bearerToken = httpServletRequest.getHeader(TOKEN_HEADER);
        if (bearerToken != null && bearerToken.startsWith(TOKEN_PREFIX)) {
            return bearerToken.substring(TOKEN_PREFIX.length());
        }
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public boolean validateClaims(Claims claims) throws AuthenticationException {
        try {
            return claims.getExpiration().after(new Date());
        } catch (Exception e) {
            throw new AuthenticationException("It seems there was an error with authentication");
        }
    }

    private Date getTokenValidityDate(final Date tokenCreateTime) {
        return new Date(tokenCreateTime.getTime() + TimeUnit.MINUTES.toMillis(ACCESS_TOKEN_VALIDITY));
    }

    private Claims parseJwtClaims(String token) {
        return jwtParser.parseSignedClaims(token).getPayload();
    }
}

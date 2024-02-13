package com.danisanga.api.security.jwt.filters;

import com.danisanga.api.security.jwt.auth.token.generator.JwtAuthTokenGenerator;
import com.danisanga.api.security.jwt.auth.token.generator.impl.JwtAuthTokenGeneratorImpl;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.naming.AuthenticationException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Spring filter that ensures there is an existing token before make any request.
 */
@Component
public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private static final Logger LOGGER = Logger.getLogger(JwtAuthorizationFilter.class.getName());

    private final JwtAuthTokenGenerator jwtAuthTokenGenerator;
    private final ObjectMapper mapper;

    /**
     * Default constructor.
     *
     * @param jwtAuthTokenGenerator injected
     * @param mapper                injected
     */
    public JwtAuthorizationFilter(final JwtAuthTokenGeneratorImpl jwtAuthTokenGenerator, final ObjectMapper mapper) {
        this.jwtAuthTokenGenerator = jwtAuthTokenGenerator;
        this.mapper = mapper;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void doFilterInternal(final HttpServletRequest httpServletRequest,
                                    final HttpServletResponse httpServletResponse,
                                    final FilterChain filterChain) throws ServletException, IOException {

        try {
            final String accessToken = jwtAuthTokenGenerator.getToken(httpServletRequest);
            if (accessToken == null) {
                filterChain.doFilter(httpServletRequest, httpServletResponse);
                return;
            }

            final Claims claims = jwtAuthTokenGenerator.getClaims(httpServletRequest);
            if (areClaimsValid(claims)) {
                final String email = claims.getSubject();
                LOGGER.log(Level.INFO, () -> String.format("Request Email : %s", email));
                LOGGER.log(Level.INFO, () -> String.format("Request Token : %s", accessToken));

                final Authentication authentication =
                        new UsernamePasswordAuthenticationToken(email, "", new ArrayList<>());
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }

        } catch (Exception e) {
            httpServletResponse.setStatus(HttpStatus.FORBIDDEN.value());
            httpServletResponse.setContentType(MediaType.APPLICATION_JSON_VALUE);
            mapper.writeValue(httpServletResponse.getWriter(), populateErrorDetails(e.getMessage()));
        }

        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }

    private boolean areClaimsValid(final Claims claims) throws AuthenticationException {
        return claims != null && jwtAuthTokenGenerator.areClaimsValid(claims);
    }

    private Map<String, Object> populateErrorDetails(final String errorMessage) {
        Map<String, Object> errorDetails = new HashMap<>();
        errorDetails.put("Error cause", "Authentication Error");
        errorDetails.put("Error message", errorMessage);
        return errorDetails;
    }
}

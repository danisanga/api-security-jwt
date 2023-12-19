package com.danisanga.api.security.jwt.auth.filters;

import com.danisanga.api.security.jwt.auth.JwtUtil;
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

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

@Component
public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private static final Logger LOGGER = Logger.getLogger(JwtAuthorizationFilter.class.getName());

    private final JwtUtil jwtUtil;
    private final ObjectMapper mapper;

    public JwtAuthorizationFilter(JwtUtil jwtUtil, ObjectMapper mapper) {
        this.jwtUtil = jwtUtil;
        this.mapper = mapper;
    }

    @Override
    protected void doFilterInternal(final HttpServletRequest request,
                                    final HttpServletResponse response,
                                    final FilterChain filterChain) throws ServletException, IOException {
        Map<String, Object> errorDetails = new HashMap<>();

        try {
            final String accessToken = jwtUtil.resolveToken(request);
            if (accessToken == null) {
                filterChain.doFilter(request, response);
                return;
            }
            LOGGER.log(Level.INFO, () -> String.format("Request Token : %s", accessToken));

            final Claims claims = jwtUtil.resolveClaims(request);
            if (claims != null && jwtUtil.validateClaims(claims)) {
                final String email = claims.getSubject();
                LOGGER.log(Level.INFO, () -> String.format("Request Email : %s", email));

                final Authentication authentication =
                        new UsernamePasswordAuthenticationToken(email, "", new ArrayList<>());
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }

        } catch (Exception e) {
            errorDetails.put("message", "Authentication Error");
            errorDetails.put("details", e.getMessage());
            response.setStatus(HttpStatus.FORBIDDEN.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);

            mapper.writeValue(response.getWriter(), errorDetails);
        }
        filterChain.doFilter(request, response);
    }
}

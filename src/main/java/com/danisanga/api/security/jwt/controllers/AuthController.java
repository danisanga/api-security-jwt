package com.danisanga.api.security.jwt.controllers;

import com.danisanga.api.security.jwt.auth.token.generator.JwtAuthTokenGenerator;
import com.danisanga.api.security.jwt.auth.token.generator.impl.JwtAuthTokenGeneratorImpl;
import com.danisanga.api.security.jwt.models.UserModel;
import com.danisanga.api.security.jwt.dtos.LoginRequestWsDTO;
import com.danisanga.api.security.jwt.dtos.responses.ErrorResponseWsDTO;
import com.danisanga.api.security.jwt.dtos.responses.LoginResponseWsDTO;
import io.jsonwebtoken.lang.Strings;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/rest/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtAuthTokenGenerator jwtAuthTokenGenerator;

    /**
     * Default constructor.
     *
     * @param authenticationManager injected
     * @param jwtAuthTokenGenerator injected
     */
    public AuthController(final AuthenticationManager authenticationManager,
                          final JwtAuthTokenGeneratorImpl jwtAuthTokenGenerator) {
        this.authenticationManager = authenticationManager;
        this.jwtAuthTokenGenerator = jwtAuthTokenGenerator;

    }

    @PostMapping(value = "/login")
    public ResponseEntity<Object> login(@RequestBody LoginRequestWsDTO loginRequestWsDTO)  {

        try {
            final Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequestWsDTO.getEmail(),
                            loginRequestWsDTO.getPassword()));

            final String email = authentication.getName();
            final UserModel userModel = new UserModel(email, Strings.EMPTY);
            final String token = jwtAuthTokenGenerator.generateToken(userModel);
            final LoginResponseWsDTO loginRes = new LoginResponseWsDTO(email,token);
            return ResponseEntity.ok(loginRes);

        }catch (final BadCredentialsException exception){
            final ErrorResponseWsDTO errorResponseWsDTO = new ErrorResponseWsDTO(HttpStatus.BAD_REQUEST,"Invalid username or password");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponseWsDTO);
        }catch (Exception e){
            final ErrorResponseWsDTO errorResponseWsDTO = new ErrorResponseWsDTO(HttpStatus.BAD_REQUEST, e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponseWsDTO);
        }
    }
}

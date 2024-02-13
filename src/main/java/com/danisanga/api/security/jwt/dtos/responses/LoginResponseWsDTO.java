package com.danisanga.api.security.jwt.dtos.responses;

public class LoginResponseWsDTO {
    private String email;
    private String token;

    public LoginResponseWsDTO(final String email, final String token) {
        this.email = email;
        this.token = token;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }
}

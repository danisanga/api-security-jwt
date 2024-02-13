package com.danisanga.api.security.jwt.dtos.responses;

import org.springframework.http.HttpStatus;

public class ErrorResponseWsDTO {
    private HttpStatus httpStatus;
    private String message;

    public ErrorResponseWsDTO(final HttpStatus httpStatus, final String message) {
        this.httpStatus = httpStatus;
        this.message = message;
    }

    public HttpStatus getHttpStatus() {
        return httpStatus;
    }

    public void setHttpStatus(HttpStatus httpStatus) {
        this.httpStatus = httpStatus;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}

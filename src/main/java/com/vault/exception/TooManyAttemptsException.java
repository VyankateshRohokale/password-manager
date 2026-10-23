package com.vault.exception;

import org.springframework.http.HttpStatus;

public class TooManyAttemptsException extends ApiException {

    public TooManyAttemptsException() {
        super(HttpStatus.TOO_MANY_REQUESTS, "Too many failed attempts. Please wait a few minutes and try again.");
    }
}

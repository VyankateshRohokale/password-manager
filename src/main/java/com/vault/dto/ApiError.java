package com.vault.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.time.Instant;
import java.util.List;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
public record ApiError(int status, String error, String message, List<FieldError> fieldErrors, Instant timestamp) {

    public record FieldError(String field, String message) {
    }

    public static ApiError of(int status, String error, String message) {
        return new ApiError(status, error, message, List.of(), Instant.now());
    }
}

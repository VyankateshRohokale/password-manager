package com.vault.dto;

public record PreloginResponse(String kdfAlgorithm, String kdfSalt, int kdfIterations) {
}

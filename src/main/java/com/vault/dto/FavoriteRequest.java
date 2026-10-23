package com.vault.dto;

import jakarta.validation.constraints.NotNull;

public record FavoriteRequest(@NotNull Boolean favorite) {
}

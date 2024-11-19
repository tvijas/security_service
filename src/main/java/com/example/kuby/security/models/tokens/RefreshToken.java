package com.example.kuby.security.models.tokens;

import lombok.Getter;

@Getter
public record RefreshToken(String refreshToken) {
}

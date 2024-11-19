package com.example.kuby.security.util.parsers;

import jakarta.servlet.http.HttpServletRequest;

import java.util.Optional;

public final class AuthHeaderParser {
    private AuthHeaderParser (){}
    public static Optional<String> recoverToken(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        return recoverToken(authHeader);
    }

    public static Optional<String> recoverToken(String headerValue) {
        if (headerValue == null || !headerValue.startsWith("Bearer "))
            return Optional.empty();
        String token = headerValue.substring(7).trim();

        if (token.isEmpty())
            return Optional.empty();

        return Optional.of(token);
    }
}

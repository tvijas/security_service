package com.example.kuby.test.utils;

import com.auth0.jwt.JWT;
import com.example.kuby.exceptions.BasicException;
import org.springframework.boot.test.context.TestComponent;
import org.springframework.http.HttpStatus;

import java.util.Map;
import java.util.UUID;

import static com.example.kuby.security.util.parsers.AuthHeaderParser.recoverToken;

@TestComponent
public class JwtPayloadParser {
    public UUID parseUserIdFromAuthHeader(String header) {
        String token = recoverToken(header).orElseThrow(() ->
                new BasicException(Map.of("Authorization", "Invalid Authorization header"), HttpStatus.BAD_REQUEST));

        return UUID.fromString(JWT.decode(token).getClaim("userId").asString());
    }
}

package com.example.kuby.security.service.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class JwtDecoderService {
    private final Algorithm algorithm;
    public Optional<DecodedJWT> decodeJwt(String jwt) {
        try {
            return Optional.of(JWT.require(algorithm).build().verify(jwt));
        } catch (JWTVerificationException ex) {
            return Optional.empty();
        }
    }

    public Optional<DecodedJWT> decodeJwtWithoutExp(String jwt) {
        try {
            return Optional.of(JWT.require(algorithm)
                    .acceptExpiresAt(Instant.now().plusMillis(1000000).getEpochSecond())
                    .build()
                    .verify(jwt));
        } catch (JWTVerificationException ex) {
            return Optional.empty();
        }
    }
}

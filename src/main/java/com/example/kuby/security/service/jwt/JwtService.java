package com.example.kuby.security.service.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.kuby.security.blacklist.BlacklistService;
import com.example.kuby.exceptions.BasicException;
import com.example.kuby.foruser.UserEntity;
import com.example.kuby.security.models.entity.tokens.AccessToken;
import com.example.kuby.security.models.entity.tokens.RefreshToken;
import com.example.kuby.security.models.entity.tokens.Tokens;
import com.example.kuby.security.models.enums.TokenActionType;
import com.example.kuby.security.repos.token.TokensRepo;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
@Service
@RequiredArgsConstructor
public class JwtService {
    private final TokensRepo tokensRepo;
    @Transactional
    public Tokens saveRefreshedTokenPair(Instant expiresAt,
                                         Instant updatedAt,
                                         Instant access_expiration,
                                         Instant refresh_expiration,
                                         UserEntity users) {
        Tokens tokens = tokensRepo.findByUsers(users).orElseThrow(() ->
                new BasicException(Map.of("user", "There are no linked tokens to you"), HttpStatus.NOT_FOUND));

        if (tokens.getUpdatedAt().plusSeconds(60).toEpochMilli() > updatedAt.toEpochMilli())
            throw new BasicException(Map.of("request","too many refresh requests"),HttpStatus.TOO_MANY_REQUESTS);

        if (!tokens.getRefreshToken().getExpiresAt().truncatedTo(ChronoUnit.SECONDS).equals(expiresAt))
            throw new BasicException(Map.of("refresh_token", "Refresh Token was used! You can use refresh token only once."), HttpStatus.BAD_REQUEST);

        tokens.getAccessToken().setExpiresAt(access_expiration);
        tokens.getRefreshToken().setExpiresAt(refresh_expiration);
        tokens.setUpdatedAt(updatedAt);

        return tokensRepo.save(tokens);
    }

    @Transactional
    public Tokens saveGeneratedTokenPair(Instant updatedAt,
                                         Instant access_expiration,
                                         Instant refresh_expiration,
                                         UserEntity users) {
        Optional<Tokens> optionalTokens = tokensRepo.findByUsers(users);
        if (optionalTokens.isEmpty())
            return tokensRepo.save(Tokens.builder()
                    .accessToken(AccessToken.builder().expiresAt(access_expiration).build())
                    .refreshToken(RefreshToken.builder().expiresAt(refresh_expiration).build())
                    .updatedAt(updatedAt)
                    .users(users)
                    .build());
        else {
            Tokens tokens = optionalTokens.get();
            tokens.getAccessToken().setExpiresAt(access_expiration);
            tokens.getRefreshToken().setExpiresAt(refresh_expiration);
            tokens.setUpdatedAt(updatedAt);

            return tokensRepo.save(tokens);
        }
    }
}


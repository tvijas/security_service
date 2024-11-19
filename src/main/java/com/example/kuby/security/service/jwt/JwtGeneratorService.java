package com.example.kuby.security.service.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.kuby.exceptions.BasicException;
import com.example.kuby.foruser.UserEntity;
import com.example.kuby.foruser.UserRepo;
import com.example.kuby.security.models.tokens.AccessToken;
import com.example.kuby.security.models.tokens.RefreshToken;
import com.example.kuby.security.models.tokens.TokenPair;
import com.example.kuby.security.models.entity.tokens.Tokens;
import com.example.kuby.security.models.enums.Provider;
import com.example.kuby.security.models.enums.TokenType;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.stream.Collectors;

import static com.example.kuby.security.util.parsers.jwt.JwtPayloadParser.*;


@Service
@RequiredArgsConstructor
public class JwtGeneratorService {
    private long accessTokenDurationInSeconds;
    private long refreshTokenDurationInSeconds;

    private final JwtValidatorService jwtValidatorService;
    private final JwtService jwtService;
    private final UserRepo userRepo;
    private final Algorithm algorithm;

    @Autowired
    public JwtGeneratorService(@Value("${security.jwt.access.token.duration.minutes:15}") long accessDuration,
                               @Value("${security.jwt.access.token.duration.days:7}") int refreshDuration,
                               JwtValidatorService jwtValidatorService, JwtService jwtService, UserRepo userRepo, Algorithm algorithm) {
        this.accessTokenDurationInSeconds = Duration.ofMinutes(accessDuration).toSeconds();
        this.refreshTokenDurationInSeconds = Duration.ofDays(refreshDuration).toSeconds();
        this.jwtValidatorService = jwtValidatorService;
        this.jwtService = jwtService;
        this.userRepo = userRepo;
        this.algorithm = algorithm;
    }

    @Transactional
    public TokenPair refreshTokens(String access_token, String refresh_token) {
        DecodedJWT decodedRefreshToken = jwtValidatorService
                .validateToken(refresh_token, TokenType.REFRESH)
                .orElseThrow(() ->
                        new BasicException(Map.of("refreshToken", "Refresh token isn't valid"), HttpStatus.UNAUTHORIZED));

        DecodedJWT decodedAccessToken = jwtValidatorService
                .validateTokenWithoutExp(access_token, TokenType.ACCESS)
                .orElseThrow(() ->
                        new BasicException(Map.of("accessToken", "Access token isn't valid"), HttpStatus.UNAUTHORIZED));

        if (!areTokensLinked(decodedAccessToken, decodedRefreshToken))
            throw new BasicException(Map.of("tokens", "Tokens are not linked too each other"), HttpStatus.BAD_REQUEST);

        Map<String, Claim> claims = parsePayloadFromJwt(refresh_token);
        Instant expiresAt = getExpiresAt(claims);
        Provider provider = getProviderFromClaims(claims);
        String email = decodedRefreshToken.getSubject();

        UserEntity user = userRepo.findByEmailAndProvider(email, provider).orElseThrow(() ->
                new BasicException(Map.of("refreshToken", "Email from token's subject not found"), HttpStatus.NOT_FOUND));

        TokenPair tokenPair;
        try {
            Instant accessTokenExpiration = calculateExpirationInstantWithMicros(accessTokenDurationInSeconds);
            Instant refreshTokenExpiration = calculateExpirationInstantWithMicros(refreshTokenDurationInSeconds);

            Tokens tokens = jwtService.saveRefreshedTokenPair(expiresAt, Instant.now(), accessTokenExpiration, refreshTokenExpiration, user);

            String accessToken = regenerateAccessTokenWithNewExpiration(decodedAccessToken, accessTokenExpiration);
            String refreshToken = generateBasicToken(user, tokens, TokenType.REFRESH, accessTokenExpiration);
            tokenPair = new TokenPair(new AccessToken(accessToken),new RefreshToken(refreshToken));

        } catch (JWTCreationException exception) {
            throw new BasicException(
                    Map.of("jwt", "Error occurred while refreshing tokens. Error description: " + exception),
                    HttpStatus.BAD_REQUEST
            );
        }
        return tokenPair;
    }

    @Transactional
    public TokenPair generateTokens(UserEntity user) {
        TokenPair tokenPair;
        try {
            Instant accessTokenExpiration = calculateExpirationInstantWithMicros(accessTokenDurationInSeconds);
            Instant refreshTokenExpiration = calculateExpirationInstantWithMicros(refreshTokenDurationInSeconds);

            Tokens tokens = jwtService
                    .saveGeneratedTokenPair(Instant.now(), accessTokenExpiration, refreshTokenExpiration, user);

            String accessToken = generateBasicToken(user, tokens, TokenType.ACCESS, accessTokenExpiration);
            String refreshToken = generateBasicToken(user, tokens, TokenType.REFRESH, refreshTokenExpiration);
            tokenPair = new TokenPair(new AccessToken(accessToken), new RefreshToken(refreshToken));

        } catch (JWTCreationException exception) {
            throw new BasicException(
                    Map.of("jwt", "Error occurred while generating tokens. Error description: " + exception),
                    HttpStatus.BAD_REQUEST
            );
        }
        return tokenPair;
    }

    public String generateTokenWithNewClaims(Map<String, Object> newClaims, DecodedJWT decodedJWT) {
        JWTCreator.Builder jwtBuilder = JWT.create();

        jwtBuilder.withSubject(decodedJWT.getSubject());
        newClaims.forEach((key, value) -> jwtBuilder.withClaim(key, value.toString()));
        jwtBuilder.withExpiresAt(decodedJWT.getExpiresAtAsInstant());

        return jwtBuilder.sign(algorithm);
    }

    public String regenerateAccessTokenWithNewExpiration(DecodedJWT decodedAccessToken, Instant newExpiration) {
        JWTCreator.Builder jwtBuilder = JWT.create();
        jwtBuilder.withSubject(decodedAccessToken.getSubject());
        decodedAccessToken.getClaims()
                .forEach((key, value) ->
                        jwtBuilder.withClaim(key, value.asString()));
        jwtBuilder.withExpiresAt(newExpiration);

        return jwtBuilder.sign(algorithm);
    }

    private String generateBasicToken(UserEntity user, Tokens tokens, TokenType tokenType, Instant expiration) {
        return JWT.create()
                .withSubject(user.getUsername())
                .withClaim("userId", user.getId().toString())
                .withClaim("jwtId", tokens.getRefreshToken().getId().toString())
                .withClaim("familyId", tokens.getId().toString())
                .withClaim("tokenType", tokenType.toString())
                .withClaim("provider", user.getProvider().toString().toUpperCase())
                .withExpiresAt(expiration)
                .sign(algorithm);
    }

    private Instant calculateExpirationInstantWithMicros(long seconds) {
        return Instant.now().plusSeconds(seconds);
    }

    private boolean areTokensLinked(DecodedJWT decodedAccessToken, DecodedJWT decodedRefreshToken) {
        return decodedAccessToken.getSubject().equals(decodedRefreshToken.getSubject());
    }

    public String addClaimsIdToJwtToken(Map<String, Object> newClaims, String jwt) {
        try {
            DecodedJWT decodedJWT = JWT.require(algorithm).build().verify(jwt);

            Map<String, Object> claims = decodedJWT.getClaims().entrySet().stream()
                    .collect(Collectors
                            .toMap(Map.Entry::getKey, entry ->
                                    entry.getValue().as(Object.class)));

            claims.putAll(newClaims);

            return JWT.create()
                    .withSubject(decodedJWT.getSubject())
                    .withPayload(claims)
                    .withExpiresAt(decodedJWT.getExpiresAt())
                    .sign(algorithm);
        } catch (JWTVerificationException | JWTCreationException exception) {
            throw new BasicException(
                    Map.of("jwt", "Error occurred while generating tokens. Error description: " + exception),
                    HttpStatus.BAD_REQUEST
            );
        }
    }
}

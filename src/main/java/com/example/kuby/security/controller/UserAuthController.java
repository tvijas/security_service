package com.example.kuby.security.controller;

import com.example.kuby.exceptions.BasicException;
import com.example.kuby.foruser.CustomUserDetails;
import com.example.kuby.foruser.UserEntity;
import com.example.kuby.security.models.enums.Provider;
import com.example.kuby.security.models.request.ChangePasswordRequest;
import com.example.kuby.security.models.request.LoginRequest;
import com.example.kuby.security.models.request.SignUpRequest;
import com.example.kuby.security.models.tokens.TokenPair;
import com.example.kuby.security.ratelimiter.WithRateLimitProtection;
import com.example.kuby.security.service.jwt.JwtGeneratorService;
import com.example.kuby.security.service.user.UserAuthService;
import com.example.kuby.security.util.annotations.validators.email.EmailExists;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

import static com.example.kuby.security.util.parsers.AuthHeaderParser.recoverToken;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
public class UserAuthController {
    private final UserAuthService userAuthService;
    private final JwtGeneratorService jwtGeneratorService;

    @PostMapping("/register")
    @WithRateLimitProtection
    public ResponseEntity<Void> register(@RequestBody @Valid SignUpRequest request) {

        userAuthService.createLocalUserAndSendSubmissionLink(request.getEmail(), request.getPassword());

        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @PostMapping("/verify/local")
    @WithRateLimitProtection
    public ResponseEntity<Void> verifyEmail(@RequestParam String code, @RequestParam String email) {

        userAuthService.verifyUserAccount(code, email);

        return ResponseEntity.ok().build();
    }

    @PostMapping("/resend-submission-link")
    @WithRateLimitProtection(rateLimit = 3, rateDuration = 180_000)
    public ResponseEntity<Void> submitEmail(@RequestParam @Valid @Email @EmailExists String email) {

        userAuthService.sendMailWithAccountSubmissionLink(email);

        return new ResponseEntity<>(HttpStatus.OK);
    }

    @PostMapping("/login")
    @WithRateLimitProtection
    public ResponseEntity<Void> login(@RequestBody @Valid LoginRequest request) {

         UserEntity user = userAuthService.authenticate(request.getEmail(), request.getPassword(), Provider.LOCAL);

        TokenPair tokenPair = jwtGeneratorService.generateTokens(user);

        return ResponseEntity.ok()
                .header("Authorization", "Bearer " + tokenPair.getAccessTokenValue())
                .header("X-Refresh-Token", tokenPair.getRefreshTokenValue())
                .build();
    }

    @PostMapping("/token/refresh")
    @WithRateLimitProtection
    public ResponseEntity<Void> refreshTokens(@RequestHeader("X-Refresh-Token") String refreshToken,
                                              @RequestHeader("Authorization") String accessToken) {
        String parsedAccessToken = recoverToken(accessToken).orElseThrow(() ->
                new BasicException(Map.of("Authorization", "Authorization header is empty or has invalid format"), HttpStatus.BAD_REQUEST));

        TokenPair tokenPair = jwtGeneratorService
                .refreshTokens(parsedAccessToken, refreshToken);

        return ResponseEntity.ok()
                .header("Authorization", "Bearer " + tokenPair.getAccessTokenValue())
                .header("X-Refresh-Token", tokenPair.getRefreshTokenValue())
                .build();
    }
    @PostMapping("/change-password")
    @WithRateLimitProtection
    public ResponseEntity<Void> changePassword(@RequestBody @Valid ChangePasswordRequest request) {

        userAuthService.cachePasswordAndSendPasswordChangeSubmissionLink(request.getEmail(), request.getPassword());

        return ResponseEntity.status(HttpStatus.ACCEPTED).build();
    }

    @PostMapping("/submit-password-change")
    @WithRateLimitProtection
    public ResponseEntity<Void> submitPasswordChange(@RequestParam String code, @RequestParam String email) {

        userAuthService.submitPasswordChange(email,code);

        return ResponseEntity.ok().build();
    }
}

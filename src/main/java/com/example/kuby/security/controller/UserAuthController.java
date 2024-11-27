package com.example.kuby.security.controller;

import com.example.kuby.exceptions.BasicException;
import com.example.kuby.security.models.enums.EmailCodeType;
import com.example.kuby.security.models.enums.Provider;
import com.example.kuby.security.models.request.ChangePasswordRequest;
import com.example.kuby.security.models.request.LoginRequest;
import com.example.kuby.security.models.request.SignUpRequest;
import com.example.kuby.security.models.tokens.TokenPair;
import com.example.kuby.security.ratelimiter.WithRateLimitProtection;
import com.example.kuby.security.service.jwt.JwtGeneratorService;
import com.example.kuby.security.service.submission.SubmissionCodeService;
import com.example.kuby.security.service.user.UserAuthService;
import com.example.kuby.foruser.UserService;
import com.example.kuby.security.util.annotations.validators.email.EmailExists;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

import static com.example.kuby.security.util.parsers.AuthHeaderParser.recoverToken;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
public class UserAuthController {
    private final UserService userService;
    private final UserAuthService userAuthService;
    private final SubmissionCodeService submissionCodeService;
    private final JwtGeneratorService jwtGeneratorService;

    @PostMapping("/register")
    @WithRateLimitProtection
    @Transactional
    public ResponseEntity<Void> register(@RequestBody @Valid SignUpRequest request) {

        userService.createLocalUser(request.getEmail(), request.getPassword());

        submissionCodeService.sendCodeToEmail(request.getEmail(), EmailCodeType.SUBMIT_EMAIL, Provider.LOCAL);

        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @PostMapping("/verify/local")
    @WithRateLimitProtection
    public ResponseEntity<Void> verifyEmail(@RequestParam String code, @RequestParam String email) {

        submissionCodeService.verifySubmissionEmailCode(code, email);

        return ResponseEntity.ok().build();
    }

    @PostMapping("/resend-submission-url")
    @WithRateLimitProtection(rateLimit = 3, rateDuration = 180_000)
    public ResponseEntity<Void> submitEmail(@RequestParam @Valid @Email @EmailExists String email) {

        submissionCodeService.sendCodeToEmail(email, EmailCodeType.SUBMIT_EMAIL, Provider.LOCAL);

        return new ResponseEntity<>(HttpStatus.OK);
    }

    @PostMapping("/login")
    @WithRateLimitProtection
    public ResponseEntity<Void> login(@RequestBody @Valid LoginRequest request) {

        TokenPair tokenPair = userAuthService
                .authenticateAndGenerateTokens(request.getEmail(),request.getPassword(),Provider.LOCAL);

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
        submissionCodeService.sendCodeToEmail(request.getEmail(), EmailCodeType.CHANGE_PASSWORD, Provider.LOCAL);

        submissionCodeService.cacheEmailAndPassword(request.getEmail(), request.getPassword());

        return ResponseEntity.status(HttpStatus.ACCEPTED).build();
    }

    @PostMapping("/summit-password-change")
    @WithRateLimitProtection
    public ResponseEntity<Void> submitPasswordChange(@RequestParam String code, @RequestParam String email) {

        String newPassword = submissionCodeService.verifyChangePasswordSubmissionEmailCode(code, email);

        userService.changePassword(email, newPassword);

        return ResponseEntity.ok().build();
    }
}

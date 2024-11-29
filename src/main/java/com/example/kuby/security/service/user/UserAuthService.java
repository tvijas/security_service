package com.example.kuby.security.service.user;

import com.example.kuby.exceptions.BasicException;
import com.example.kuby.foruser.CustomUserDetails;
import com.example.kuby.foruser.CustomUserPrincipal;
import com.example.kuby.foruser.UserEntity;
import com.example.kuby.foruser.UserService;
import com.example.kuby.security.constant.UrlBase;
import com.example.kuby.security.models.enums.Provider;
import com.example.kuby.security.models.tokens.TokenPair;
import com.example.kuby.security.service.email_sending.EmailSenderService;
import com.example.kuby.security.service.jwt.JwtGeneratorService;
import com.example.kuby.security.service.submission.SubmissionCodeCachingService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;

@Service
@RequiredArgsConstructor
public class UserAuthService {
    private final AuthenticationManager authenticationManager;
    private final UserService userService;
    private final EmailSenderService emailSenderService;
    private final SubmissionCodeCachingService submissionCodeCachingService;

    @Transactional
    public void createLocalUserAndSendSubmissionLink(String email, String password) {
        userService.createLocalUser(email, password);

        sendMailWithAccountSubmissionLink(email);
    }

    @Transactional
    public void sendMailWithAccountSubmissionLink(String email) {
        if (userService
                .findByEmailAndProvider(email, Provider.LOCAL)
                .orElseThrow(() ->
                        new BasicException(Map.of("email", "User with such email not found."), HttpStatus.NOT_FOUND))
                .isEmailSubmitted())
            throw new BasicException(Map.of("email", "Email is already submitted"), HttpStatus.BAD_REQUEST);

        String code = submissionCodeCachingService.createEmailSubmissionCodeWithExpiration(email);

        emailSenderService.sendSubmissionLink(email, code, UrlBase.VERIFY_LOCAL);
    }

    @Transactional
    public void verifyUserAccount(String code, String email) {
        if (!submissionCodeCachingService.isEmailSubmissionCodeExists(code, email))
            throw new BasicException(Map.of("code", "Code is expired or not exists "), HttpStatus.NOT_FOUND);

        userService.updateIsEmailSubmittedByEmailAndProvider(email, Provider.LOCAL);
    }

    @Transactional
    public void cachePasswordAndSendPasswordChangeSubmissionLink(String email, String password) {
        userService.findByEmailAndProvider(email, Provider.LOCAL).orElseThrow(() ->
                new BasicException(Map.of("email", "User with such email not found."), HttpStatus.NOT_FOUND));

        submissionCodeCachingService.cacheEmailAndNewPasswordUntilSubmission(email, password);

        sendMailWithPasswordChangeSubmissionLink(email);
    }

    public void sendMailWithPasswordChangeSubmissionLink(String email) {
        String code = submissionCodeCachingService.createChangePasswordSubmissionCodeWithExpiration(email);

        emailSenderService.sendSubmissionLink(email, code, UrlBase.SUBMIT_PASSWORD_CHANGE);
    }

    @Transactional
    public void submitPasswordChange(String email, String code) {
        if (!submissionCodeCachingService.isChangePasswordSubmissionCodeExists(code, email))
            throw new BasicException(Map.of("code", "Code not found"), HttpStatus.NOT_FOUND);

        String newPassword = submissionCodeCachingService.popPasswordByEmail(email);

        userService.changePassword(email, newPassword);
    }

    @Transactional
    public UserEntity authenticate(String email, String password, Provider provider) {
        CustomUserPrincipal customUserPrincipal = new CustomUserPrincipal(email, provider);
        UsernamePasswordAuthenticationToken usernamePassword = new UsernamePasswordAuthenticationToken(customUserPrincipal, password);
        Authentication authUser = authenticationManager.authenticate(usernamePassword);

        if (!authUser.isAuthenticated())
            throw new BasicException(Map.of("email_or_password", "Email or password isn't correct"), HttpStatus.NOT_FOUND);

        if (authUser instanceof CredentialsContainer container)
            container.eraseCredentials();

        return (UserEntity) authUser.getPrincipal();
    }
}

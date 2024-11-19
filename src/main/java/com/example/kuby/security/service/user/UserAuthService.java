package com.example.kuby.security.service.user;

import com.example.kuby.exceptions.BasicException;
import com.example.kuby.foruser.UserEntity;
import com.example.kuby.foruser.UserRepo;
import com.example.kuby.security.models.enums.Provider;
import com.example.kuby.security.models.tokens.TokenPair;
import com.example.kuby.security.service.jwt.JwtGeneratorService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;

@Service
@RequiredArgsConstructor
public class UserAuthService {
    private final UserRepo userRepo;
    private final AuthenticationManager authenticationManager;
    private final JwtGeneratorService jwtGeneratorService;
    @Transactional
    public TokenPair authenticateAndGenerateTokens(String login, String password){
        UserEntity userEntity = userRepo.findByLogin(login)
                .orElseThrow(() -> new BasicException(Map.of("login_or_password", "Email or password isn't correct"), HttpStatus.NOT_FOUND));

        if (!userEntity.getProvider().equals(Provider.LOCAL))
            throw new BasicException(Map.of("login_or_password", "Email or password isn't correct"), HttpStatus.NOT_FOUND);

        if (!userEntity.isEmailSubmitted())
            throw new BasicException(Map.of("email", "Email is not verified"), HttpStatus.BAD_REQUEST);

        UsernamePasswordAuthenticationToken usernamePassword = new UsernamePasswordAuthenticationToken(login, password);
        Authentication authUser = authenticationManager.authenticate(usernamePassword);

        if (!authUser.isAuthenticated())
            throw new BasicException(Map.of("login_or_password", "Email or password isn't correct"), HttpStatus.NOT_FOUND);

        return jwtGeneratorService.generateTokens(userEntity);
    }
}

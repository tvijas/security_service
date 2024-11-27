package com.example.kuby.security.service.user;

import com.example.kuby.exceptions.BasicException;
import com.example.kuby.foruser.CustomUserPrincipal;
import com.example.kuby.foruser.UserEntity;
import com.example.kuby.foruser.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
@RequiredArgsConstructor
public class UserAuthenticationProvider implements AuthenticationProvider {
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        CustomUserPrincipal userPrincipal = (CustomUserPrincipal) authentication.getPrincipal();
        String password = (String) authentication.getCredentials();

        UserEntity user = userService.findByEmailAndProvider(userPrincipal.email(), userPrincipal.provider()).orElseThrow(() ->
                new BasicException(Map.of("email_or_password", "Email or password isn't correct"), HttpStatus.BAD_REQUEST));

        if (!passwordEncoder.matches(password, user.getPassword()))
            throw new BasicException(Map.of("email_or_password", "Email or password isn't correct"), HttpStatus.BAD_REQUEST);

        if (!user.isEnabled())
            throw new BasicException(Map.of("email", "Email is not verified"), HttpStatus.BAD_REQUEST);


        return new UsernamePasswordAuthenticationToken(
                user,
                password,
                user.getAuthorities()
        );
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}

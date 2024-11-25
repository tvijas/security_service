package com.example.kuby.security.service.user;

import com.example.kuby.security.models.CustomOAuth2User;
import com.example.kuby.security.models.tokens.TokenPair;
import com.example.kuby.security.service.jwt.JwtGeneratorService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
@Component
@RequiredArgsConstructor
public class OauthSuccessHandler implements AuthenticationSuccessHandler {
    private final JwtGeneratorService jwtGeneratorService;
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        CustomOAuth2User oauthUser = (CustomOAuth2User) authentication.getPrincipal();
        TokenPair tokenPair = jwtGeneratorService.generateTokens(oauthUser.getUser());
        response.addHeader("Authorization", "Bearer " + tokenPair.getAccessTokenValue());
        response.addHeader("X-Refresh-Token", tokenPair.getRefreshTokenValue());
        response.setStatus(HttpStatus.OK.value());
//                            response.sendRedirect(frontendUrl); ??? TODO maybe not needed
    }
}

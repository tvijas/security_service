package com.example.kuby.security.filter;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.kuby.foruser.CustomUserDetails;
import com.example.kuby.foruser.UserCache;
import com.example.kuby.security.models.enums.TokenType;
import com.example.kuby.security.ratelimiter.GlobalRateLimit;
import com.example.kuby.security.service.jwt.JwtPayloadValidatorService;
import com.example.kuby.security.service.jwt.JwtValidatorService;
import com.example.kuby.security.service.user.UserService;
import com.example.kuby.security.util.PermittedUrls;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

import static com.example.kuby.security.util.parsers.AuthHeaderParser.recoverToken;
import static com.example.kuby.security.util.parsers.jwt.JwtPayloadParser.getIdFromClaimsByKey;
import static com.example.kuby.security.util.parsers.jwt.JwtPayloadParser.getProviderFromClaims;


@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {
    private final UserService userService;
    private final GlobalRateLimit globalRateLimit;
    @Value("${global.rate.limit.turn.on}")
    private boolean turnOnRateLimit;
    private final JwtPayloadValidatorService jwtPayloadValidatorService;
    private final JwtValidatorService jwtValidatorService;
    private final PermittedUrls permittedUrls;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (turnOnRateLimit) {
            if (!globalRateLimit.allowRequest(getClientIpAddress(request), System.currentTimeMillis())) {
                response.setStatus(429);
                return;
            }
        }

        if (permittedUrls.isPermitAllRequest(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        Optional<String> token = recoverToken(request);
        if (token.isEmpty()) {
            response.setStatus(401);
            return;
        }

        Optional<DecodedJWT> optionalDecodedAccessToken = jwtValidatorService
                .validateToken(token.get(), TokenType.ACCESS);

        if (optionalDecodedAccessToken.isEmpty()) {
            response.setStatus(401);
            return;
        }
        DecodedJWT decodedAccessToken = optionalDecodedAccessToken.get();

        boolean isTokenClaimValid = jwtPayloadValidatorService.isTokenClaimValid(
                getIdFromClaimsByKey(decodedAccessToken.getClaims(), "jwtId").toString(),
                decodedAccessToken, response
        );

        if (!isTokenClaimValid) {
            response.setStatus(420);
            return;
        }

        Optional<UserCache> userCache = userService.loadUserByUsername(
                decodedAccessToken.getSubject(),
                getProviderFromClaims(decodedAccessToken.getClaims())
        );

        if (userCache.isEmpty() || !userCache.get().isEnabled()) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            filterChain.doFilter(request, response);
            return;
        }

        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userCache.get(), null, userCache.get().getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authentication);

        filterChain.doFilter(request, response);
    }

    private String getClientIpAddress(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty()) {
            ip = request.getRemoteAddr();
        }
        return ip;
    }
}

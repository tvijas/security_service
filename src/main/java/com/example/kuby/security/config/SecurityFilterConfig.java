package com.example.kuby.security.config;

import com.example.kuby.security.filter.JwtAuthFilter;
import com.example.kuby.security.service.user.CustomOAuth2UserService;
import com.example.kuby.security.service.user.OauthFailureHandler;
import com.example.kuby.security.service.user.OauthSuccessHandler;
import com.example.kuby.security.service.user.UserAuthenticationEntryPoint;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true)
@RequiredArgsConstructor
public class SecurityFilterConfig {
    @Bean
    SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            JwtAuthFilter jwtAuthFilter,
            CustomOAuth2UserService oauthUserService,
            UserAuthenticationEntryPoint userAuthenticationEntryPoint,
            OauthFailureHandler oauthFailureHandler,
            OauthSuccessHandler oauthSuccessHandler
    ) throws Exception {
        return http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(withDefaults())
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authorize -> {
                            authorize
                                    .requestMatchers(
                                            HttpMethod.GET,
                                            "/v3/api-docs/**",
                                            "/swagger-ui/**",
                                            "/swagger-ui.html")
                                    .permitAll()

                                    .requestMatchers(HttpMethod.POST, "/api/user/**").permitAll()

                                    .requestMatchers(HttpMethod.GET, "/login/oauth2/code/google/**").permitAll()
                                    .requestMatchers(HttpMethod.GET, "/oauth2/authorization/google").permitAll()

                                    .anyRequest().authenticated();
                        }
                )
                .oauth2Login(auth -> {
                    auth.userInfoEndpoint(uiepc ->
                            uiepc.userService(oauthUserService));
                    auth.successHandler(oauthSuccessHandler);
                    auth.failureHandler(oauthFailureHandler);
                })
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(httpSecurityExceptionHandlingConfigurer ->
                        httpSecurityExceptionHandlingConfigurer.authenticationEntryPoint(userAuthenticationEntryPoint))
                .build();
    }
}


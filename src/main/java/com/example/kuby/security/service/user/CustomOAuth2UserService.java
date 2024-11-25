package com.example.kuby.security.service.user;

import com.example.kuby.foruser.UserEntity;
import com.example.kuby.security.models.CustomOAuth2User;
import com.example.kuby.security.models.enums.Provider;
import com.example.kuby.security.models.enums.UserRoles;
import com.example.kuby.foruser.UserRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Objects;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
    private final UserRepo usersRepo;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        String email;
        String providerId;
        Provider provider;

        switch (userRequest.getClientRegistration().getRegistrationId()) {
            case "google" -> {
                email = oAuth2User.getAttribute("email");
                providerId = oAuth2User.getAttribute("sub");
                provider = Provider.GOOGLE;
            }
            default -> throw
                    new OAuth2AuthenticationException("Unsupported provider: " + userRequest.getClientRegistration().getRegistrationId());
        }
        Optional<UserEntity> optionalUser = usersRepo.findByProviderIdAndProvider(providerId,provider);

        if (optionalUser.isPresent()) {
            UserEntity existingUser = optionalUser.get();
            if (!existingUser.getEmail().equals(Objects.requireNonNull(email))) {
                existingUser.setEmail(email);
                usersRepo.save(existingUser);
            }
            return new CustomOAuth2User(existingUser, oAuth2User.getAttributes());
        } else {
            return new CustomOAuth2User(usersRepo.save(UserEntity.builder()
                    .email(email)
                    .provider(provider)
                    .providerId(providerId)
                    .registrationDate(LocalDateTime.now())
                    .isEmailSubmitted(false)
                    .roles(UserRoles.USER)
                    .build()),
                    oAuth2User.getAttributes());
        }
    }

}


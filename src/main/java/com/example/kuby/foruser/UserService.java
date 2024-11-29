package com.example.kuby.foruser;

import com.example.kuby.exceptions.BasicException;
import com.example.kuby.security.models.enums.Provider;
import com.example.kuby.security.models.enums.UserRole;
import com.example.kuby.security.repos.token.TokensRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;


@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepo userRepo;
    private final TokensRepo tokensRepo;
    private final PasswordEncoder encoder;
    @Transactional
    public void createLocalUser(String email, String password) {
        if (userRepo.existsByEmailAndProvider(email, Provider.LOCAL))
            throw new BasicException(Map.of("email", "Email is already taken"), HttpStatus.BAD_REQUEST);

        userRepo.save(UserEntity.builder()
                .email(email)
                .password(encoder.encode(password))
                .isEmailSubmitted(false)
                .registrationDate(LocalDateTime.now())
                .provider(Provider.LOCAL)
                .roles(UserRole.USER)
                .build());
    }
    public void updateIsEmailSubmittedByEmailAndProvider(String email, Provider provider){
        if (userRepo.updateIsEmailSubmittedByEmailAndProvider(email, provider) != 1)
            throw new BasicException(Map.of("email", "User with such email not found"), HttpStatus.NOT_FOUND);
    }

    public Optional<UserEntity> findByEmailAndProvider(String email, Provider provider){
        return userRepo.findByEmailAndProvider(email,provider);
    }

    @Transactional
    public void deleteUserById(UUID userId) {
        UserEntity users = userRepo.findById(userId).orElseThrow(() ->
                new BasicException(Map.of("userId", "User with such id not found"), HttpStatus.NOT_FOUND));
        tokensRepo.deleteByUsers(users);
        userRepo.delete(users);
    }

    @Transactional
    public void changePassword(String email, String password) {
        UserEntity user = userRepo.findByEmailAndProvider(email, Provider.LOCAL).orElseThrow(() ->
                new BasicException(Map.of("email", "User with such email not found"), HttpStatus.NOT_FOUND));

        user.setPassword(encoder.encode(password));

        userRepo.save(user);
    }
}
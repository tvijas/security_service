package com.example.kuby.test.utils;

import com.example.kuby.foruser.UserEntity;
import com.example.kuby.security.models.enums.Provider;
import com.example.kuby.security.models.enums.UserRole;
import com.example.kuby.foruser.UserRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.TestComponent;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;

@TestComponent
@RequiredArgsConstructor
public class DbUtils {
    private final UserRepo userRepo;
    @Value("${spring.mail.username}")
    private String testEmail;
    public static int userCount = 0;
    @Autowired
    PasswordEncoder passwordEncoder;

    public UserEntity createUser() {
        String uniqueEmail = (userCount == 0) ? testEmail : userCount + testEmail;
        UserEntity user = UserEntity.builder()
                .email(uniqueEmail)
                .password(passwordEncoder.encode("18-Bad-Boy-18"))
                .isEmailSubmitted(true)
                .provider(Provider.LOCAL)
                .registrationDate(LocalDateTime.now())
                .roles(UserRole.USER)
                .build();

        userRepo.save(user);
        userCount++;
        return user;
    }
}

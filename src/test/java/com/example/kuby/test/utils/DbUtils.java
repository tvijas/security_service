package com.example.kuby.test.utils;

import com.example.kuby.foruser.UserEntity;
import com.example.kuby.security.models.enums.Provider;
import com.example.kuby.security.models.enums.UserRoles;
import com.example.kuby.foruser.UserRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.TestComponent;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

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
        String uniqueLogin = (userCount == 0) ? "somelogin" : userCount + "somelogin";
        UserEntity user = UserEntity.builder()
                .email(uniqueEmail)
                .login(uniqueLogin)
                .password(passwordEncoder.encode("18-Bad-Boy-18"))
                .isEmailSubmitted(true)
                .provider(Provider.LOCAL)
                .registrationDate(LocalDateTime.now())
                .roles(UserRoles.USER)
                .build();

        userRepo.save(user);
        userCount++;
        return user;
    }
}

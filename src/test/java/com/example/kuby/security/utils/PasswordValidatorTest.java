package com.example.kuby.security.utils;

import com.example.kuby.security.util.annotations.validators.password.PasswordValidator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.boot.test.context.SpringBootTest;


import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest(classes = {PasswordValidatorTest.class})
public class PasswordValidatorTest {
    private final PasswordValidator validator = new PasswordValidator();

    @Test
    void testNullPassword() {

        assertFalse(validator.validate(null));
    }

    @Test
    void testEmptyPassword() {
        assertFalse(validator.validate(""));
    }

    @ParameterizedTest
    @CsvSource({
            "Short1!",
            "Aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1!",
            "PASSWORD123!",
            "password123!",
            "Password!",
            "Password123",
            "Password123#",
            "ФімозПароля123@",
            "Pass word 123!",
            "Passssssword123!"
    })
    void test(String password) {
        assertTrue(validator.validate(password));
    }
}


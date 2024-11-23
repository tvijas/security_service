package com.example.kuby.security.utils;

import com.example.kuby.security.util.annotations.validators.password.PasswordValidator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.passay.PasswordData;
import org.passay.RuleResult;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest(classes = {PasswordValidatorTest.class})
public class PasswordValidatorTest {
    private final PasswordValidator validator = new PasswordValidator();

    @Test
    void testNullPassword() {
        Optional<org.passay.PasswordValidator> result = validator.validate(null);
        assertFalse(result.isEmpty());
    }

    @Test
    void testEmptyPassword() {
        Optional<org.passay.PasswordValidator> result = validator.validate("");
        assertFalse(result.isEmpty());
    }
    @ParameterizedTest
    @CsvSource({
            "Short1!, TOO_SHORT",
            "Aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1!, TOO_LONG",
            "PASSWORD123!, INSUFFICIENT_LOWERCASE",
            "password123!, INSUFFICIENT_UPPERCASE",
            "Password!, INSUFFICIENT_DIGIT",
            "Password123, INSUFFICIENT_CUSTOM_SPECIAL",
            "Password123#, INSUFFICIENT_CUSTOM_SPECIAL",
            "ФімозПароля123@, INSUFFICIENT_LOWERCASE",
            "Pass word 123!, ALLOWED_MATCH",
            "Passssssword123!, ILLEGAL_REPEATED_CHARS"
    })
    void test(String password, String expectedErrorCode) {
        Optional<org.passay.PasswordValidator> result = validator.validate(password);
        assertTrue(result.isPresent());

        RuleResult ruleResult = result.get().validate(new PasswordData(password));
        assertTrue(ruleResult.getDetails().stream()
                .anyMatch(d -> d.getErrorCode().equals(expectedErrorCode)));
    }
}


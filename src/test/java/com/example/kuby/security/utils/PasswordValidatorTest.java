package com.example.kuby.security.utils;

import com.example.kuby.security.util.annotations.validators.password.PasswordValidator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
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

    @Test
    void testPasswordTooShort() {
        String password = "Short1!";
        Optional<org.passay.PasswordValidator> result = validator.validate(password);
        assertTrue(result.isPresent());

        RuleResult ruleResult = result.get().validate(new PasswordData(password));
        assertTrue(ruleResult.getDetails().stream()
                .anyMatch(d -> d.getErrorCode().equals("TOO_SHORT")));
    }

    @Test
    void testPasswordTooLong() {
        String longPassword = "A" + "a".repeat(100) + "1!";
        Optional<org.passay.PasswordValidator> result = validator.validate(longPassword);
        assertTrue(result.isPresent());

        RuleResult ruleResult = result.get().validate(new PasswordData(longPassword));
        assertTrue(ruleResult.getDetails().stream()
                .anyMatch(d -> d.getErrorCode().equals("TOO_LONG")));
    }

    @Test
    void testPasswordMissingLowercase() {
        String password = "PASSWORD123!";
        Optional<org.passay.PasswordValidator> result = validator.validate(password);
        assertTrue(result.isPresent());

        RuleResult ruleResult = result.get().validate(new PasswordData(password));
        assertTrue(ruleResult.getDetails().stream()
                .anyMatch(d -> d.getErrorCode().equals("INSUFFICIENT_LOWERCASE")));
    }

    @Test
    void testPasswordMissingUppercase() {
        String password = "password123!";
        Optional<org.passay.PasswordValidator> result = validator.validate(password);
        assertTrue(result.isPresent());

        RuleResult ruleResult = result.get().validate(new PasswordData(password));
        assertTrue(ruleResult.getDetails().stream()
                .anyMatch(d -> d.getErrorCode().equals("INSUFFICIENT_UPPERCASE")));
    }

    @Test
    void testPasswordMissingDigit() {
        String password = "Password!";
        Optional<org.passay.PasswordValidator> result = validator.validate(password);
        assertTrue(result.isPresent());

        RuleResult ruleResult = result.get().validate(new PasswordData(password));
        assertTrue(ruleResult.getDetails().stream()
                .anyMatch(d -> d.getErrorCode().equals("INSUFFICIENT_DIGIT")));
    }

    @Test
    void testPasswordMissingSpecialCharacter() {
        String password = "Password123";
        Optional<org.passay.PasswordValidator> result = validator.validate(password);
        assertTrue(result.isPresent());

        RuleResult ruleResult = result.get().validate(new PasswordData(password));
        assertTrue(ruleResult.getDetails().stream()
                .anyMatch(d -> d.getErrorCode().equals("INSUFFICIENT_CUSTOM_SPECIAL")));
    }

    @Test
    void testPasswordWithInvalidCharacters_case_1() {
        String password = "Password123#";
        Optional<org.passay.PasswordValidator> result = validator.validate(password);
        assertTrue(result.isPresent());

        RuleResult ruleResult = result.get().validate(new PasswordData(password));
        assertTrue(ruleResult.getDetails().stream()
                .anyMatch(d -> d.getErrorCode().equals("INSUFFICIENT_CUSTOM_SPECIAL")));
    }
    @Test
    void testPasswordWithInvalidCharacters_case_2() {
        String password = "ФімозПароля123@";
        Optional<org.passay.PasswordValidator> result = validator.validate(password);
        assertTrue(result.isPresent());

        RuleResult ruleResult = result.get().validate(new PasswordData(password));
        assertTrue(ruleResult.getDetails().stream()
                .anyMatch(d -> d.getErrorCode().equals("INSUFFICIENT_LOWERCASE")));
    }

    @Test
    void testPasswordWithWhitespace() {
        String password = "Pass word 123!";
        Optional<org.passay.PasswordValidator> result = validator.validate(password);
        assertTrue(result.isPresent());

        RuleResult ruleResult = result.get().validate(new PasswordData(password));
        assertTrue(ruleResult.getDetails().stream()
                .anyMatch(d -> d.getErrorCode().equals("ALLOWED_MATCH")));
    }

    @Test
    void testPasswordWithRepeatedCharacters() {
        String password = "Passssssword123!";
        Optional<org.passay.PasswordValidator> result = validator.validate(password);
        assertTrue(result.isPresent());

        RuleResult ruleResult = result.get().validate(new PasswordData(password));
        assertTrue(ruleResult.getDetails().stream()
                .anyMatch(d -> d.getErrorCode().equals("ILLEGAL_REPEATED_CHARS")));
    }
}


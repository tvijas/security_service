package com.example.kuby.security.util.annotations.validators.password;

import org.passay.*;

import java.util.Arrays;
import java.util.List;

import static com.example.kuby.security.constant.PasswordSize.MAX_SIZE;
import static com.example.kuby.security.constant.PasswordSize.MIN_SIZE;

public class PasswordValidator {
    //    private static final Pattern LOWERCASE = Pattern.compile("[a-z]");
//    private static final Pattern UPPERCASE = Pattern.compile("[A-Z]");
//    private static final Pattern DIGIT = Pattern.compile("\\d");
//    private static final Pattern SPECIAL = Pattern.compile("[@$!%*?&_\\-]");
//
//    public ValidationResult validatePassword(String password) {
//        if (password == null)
//            return ValidationResult.error("Password cannot be null");
//
//        if (password.length() < MIN_SIZE || password.length() > MAX_SIZE)
//            return ValidationResult.error(
//                    String.format("Password length must be between %d and %d characters", MIN_SIZE, MAX_SIZE));
//
//        List<String> violations = new ArrayList<>();
//
//        if (!LOWERCASE.matcher(password).find()) {
//            violations.add("lowercase letter");
//        }
//        if (!UPPERCASE.matcher(password).find()) {
//            violations.add("uppercase letter");
//        }
//        if (!DIGIT.matcher(password).find()) {
//            violations.add("digit");
//        }
//        if (!SPECIAL.matcher(password).find()) {
//            violations.add("special character");
//        }
//
//        if (!violations.isEmpty())
//            return ValidationResult.error(
//                    "Password must contain: " + String.join(", ", violations));
//
//        return ValidationResult.success();
//    }
    public ValidationResult validatePassword(String password) {
        if (password == null) {
            return ValidationResult.error("Password cannot be null");
        }
        org.passay.PasswordValidator validator = new org.passay.PasswordValidator(Arrays.asList(
                new LengthRule(MIN_SIZE, MAX_SIZE),
                new CharacterRule(EnglishCharacterData.LowerCase, 1),
                new CharacterRule(EnglishCharacterData.UpperCase, 1),
                new CharacterRule(EnglishCharacterData.Digit, 1),
                new CharacterRule(EnglishCharacterData.Special, 1),
                new AllowedRegexRule("^[a-zA-Z0-9@$!%*?&_-]+$"),
                new WhitespaceRule()
        ));

        PasswordData passwordData = new PasswordData(password);
        RuleResult result = validator.validate(passwordData);
        if (result.isValid()) {
            return ValidationResult.success();
        } else {
            List<String> messages = validator.getMessages(result);
            String violations = String.join(", ", messages);
            return ValidationResult.error("Password must meet the following requirements: " + violations);
        }
    }
}


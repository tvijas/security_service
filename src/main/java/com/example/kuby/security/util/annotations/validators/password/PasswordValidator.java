package com.example.kuby.security.util.annotations.validators.password;

import org.passay.*;

import java.util.List;
import java.util.Optional;

import static com.example.kuby.security.constant.Password.MAX_SIZE;
import static com.example.kuby.security.constant.Password.MIN_SIZE;

public final class PasswordValidator {
    private final List<org.passay.PasswordValidator> passwordValidators = List.of(
            new org.passay.PasswordValidator(new LengthRule(MIN_SIZE, MAX_SIZE)),
            new org.passay.PasswordValidator(new RepeatCharactersRule()),
            new org.passay.PasswordValidator(new CharacterRule(EnglishCharacterData.LowerCase, 1)),
            new org.passay.PasswordValidator(new CharacterRule(EnglishCharacterData.UpperCase, 1)),
            new org.passay.PasswordValidator(new CharacterRule(EnglishCharacterData.Digit, 1)),
            new org.passay.PasswordValidator(new CharacterRule(CustomCharacterData.Special, 1)),
            new org.passay.PasswordValidator(new AllowedRegexRule("^[a-zA-Z0-9@$!%*?&_-]+$"))
    );

    public Optional<org.passay.PasswordValidator> validate(String password) {
        if (password == null || password.trim().isEmpty()) {
            return Optional.of(new org.passay.PasswordValidator());
        }

        PasswordData passwordData = new PasswordData(password);

        return passwordValidators.stream()
                .filter(passwordValidator -> !passwordValidator.validate(passwordData).isValid())
                .findFirst();
    }
}


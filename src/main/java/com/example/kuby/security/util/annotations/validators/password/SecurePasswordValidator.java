package com.example.kuby.security.util.annotations.validators.password;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class SecurePasswordValidator implements ConstraintValidator<SecurePassword, String> {
    private final PasswordValidator passwordValidator = new PasswordValidator();

    @Override
    public boolean isValid(String password, ConstraintValidatorContext context) {
        if (password == null) return false;

        ValidationResult result = passwordValidator.validatePassword(password);

        if (!result.isValid()) {
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate(result.getMessage())
                    .addConstraintViolation();
        }

        return result.isValid();
    }
}

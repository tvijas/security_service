package com.example.kuby.security.util.annotations.validators.password;

import lombok.extern.slf4j.Slf4j;
import org.passay.*;

import java.util.List;
import java.util.concurrent.*;

import static com.example.kuby.security.constant.Password.MAX_SIZE;
import static com.example.kuby.security.constant.Password.MIN_SIZE;
@Slf4j
public class PasswordValidator {
    private final org.passay.PasswordValidator passwordValidator = new org.passay.PasswordValidator(List.of(
            new LengthRule(MIN_SIZE, MAX_SIZE),
            new RepeatCharactersRule(),
            new CharacterRule(EnglishCharacterData.LowerCase, 1),
            new CharacterRule(EnglishCharacterData.UpperCase, 1),
            new CharacterRule(EnglishCharacterData.Digit, 1),
            new CharacterRule(CustomCharacterData.Special, 1),
            new AllowedRegexRule("^[a-zA-Z0-9@$!%*?&_-]+$")
    ));

    private static final long TIMEOUT_MS = 100;

    public boolean validate(String password) {
        if (password == null || password.trim().isEmpty()) {
            return false;
        }
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            Future<RuleResult> future = executor.submit(() ->
                    passwordValidator.validate(new PasswordData(password))
            );
            RuleResult result = future.get(TIMEOUT_MS, TimeUnit.MILLISECONDS);

            return result.isValid();
        } catch (TimeoutException e){
            log.error("Password validation timed out. Password: {}", password);
            throw new RuntimeException(e);
        } catch (ExecutionException | InterruptedException e) {
            throw new RuntimeException(e);
        }
    }
}

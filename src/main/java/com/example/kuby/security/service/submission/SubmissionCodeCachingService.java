package com.example.kuby.security.service.submission;

import com.example.kuby.security.constant.RedisPrefixes;
import com.example.kuby.security.models.enums.Provider;
import com.example.kuby.security.util.generate.CodeGenerator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

import static com.example.kuby.security.constant.RedisPrefixes.*;

@Service
@Slf4j
@RequiredArgsConstructor
class SubmissionCodeCachingService {

    private final StringRedisTemplate redisTemplate;
    private final CodeGenerator codeGenerator;

    public String createEmailSubmissionCodeWithExpiration(String email, Provider provider) {

        String code = codeGenerator.generateCode();

        redisTemplate.opsForValue().set(EMAIL_SUBMISSION_CODE_PREFIX + code + ":" + provider,
                email,Duration.ofMinutes(5));

        return code;
    }

    public boolean isEmailSubmissionCodeExists(String code, String email, Provider provider) {
        String value = redisTemplate.opsForValue().get(EMAIL_SUBMISSION_CODE_PREFIX + code + ":" + provider);
        return value != null && value.equals(email);
    }

    public String createChangePasswordSubmissionCodeWithExpiration(String email) {
        String code = codeGenerator.generateCode();

        redisTemplate.opsForValue().set(PASSWORD_CHANGE_SUBMISSION_CODE_PREFIX + code,
                email,Duration.ofMinutes(5));

        return code;
    }

    public void cacheEmailAndNewPasswordUntilSubmission(String email, String password) {
        redisTemplate.opsForValue().set(NEW_PASSWORD + email, password,Duration.ofMinutes(5));
    }

    public Boolean isChangePasswordSubmissionCodeExists(String code, String email) {
        String value = redisTemplate.opsForValue().getAndDelete(PASSWORD_CHANGE_SUBMISSION_CODE_PREFIX + code);
        return value != null && value.equals(email);
    }

    public String popPasswordByEmail(String email) {
        return redisTemplate.opsForValue().getAndDelete(NEW_PASSWORD + email);
    }
}
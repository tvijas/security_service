package com.example.kuby.security.models.request;

import com.example.kuby.security.util.annotations.validators.email.EmailExists;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class SignUpRequest {
    @Email(message = "Isn't email")
    @NotBlank(message = "Email is blank")
    @Size(max = 40, message = "Email is too long")
    @EmailExists
    private final String email;
    @NotBlank(message = "Login is blank")
    @Size(min = 5,max = 15, message = "Login min size is 5 characters up to max 15 characters")
    @Pattern(regexp = "^[a-zA-Z0-9]+$",message = "Login must contain ")
    private final String login;
    @NotBlank(message = "Password is blank")
    @Size(min = 9, max = 30, message = "Password size should be from 9 to 30 characters")
    @Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&_-])[A-Za-z\\d@$!%*#?&_-]+$",
            message = "Password must contain at least one uppercase letter, one lowercase letter, one number and one special character")
    private final String password;
}

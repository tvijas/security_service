package com.example.kuby.foruser;

import com.example.kuby.exceptions.BasicException;
import com.example.kuby.security.models.enums.Provider;
import com.example.kuby.security.models.enums.UserRole;
import com.example.kuby.todolist.Task;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.*;

@Data
@Entity
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "users", indexes = {
        @Index(name = "users_provider_email_idx", columnList = "provider, email"),
        @Index(name = "users_provider_provider_id_idx", columnList = "provider, provider_id")
})
public class UserEntity implements CustomUserDetails, Serializable {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;
    @Column(nullable = false)
    private String email;
    private String password;
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Provider provider;
    private String providerId;
    private LocalDateTime lastActiveDate;
    private LocalDateTime registrationDate;
    @Column(columnDefinition = "BOOLEAN DEFAULT false", nullable = false)
    private boolean isEmailSubmitted;
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private UserRole roles;
    @OneToMany(mappedBy = "creator", fetch = FetchType.LAZY)
    private List<Task> taskList = new ArrayList<>();

    @PrePersist
    public void prePersist() {
        if (lastActiveDate == null) lastActiveDate = LocalDateTime.now();
        if (registrationDate == null) registrationDate = LocalDateTime.now();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        if (this.roles == UserRole.ADMIN) {
            return List.of(new SimpleGrantedAuthority("ROLE_ADMIN"), new SimpleGrantedAuthority("ROLE_USER"));
        }
        return Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"));
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public CustomUserPrincipal getPrincipal() {
        return new CustomUserPrincipal(this.email, this.provider);
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return this.isEmailSubmitted;
    }

}
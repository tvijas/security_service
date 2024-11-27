package com.example.kuby.foruser;

import com.example.kuby.security.models.enums.Provider;
import com.example.kuby.security.models.enums.UserRole;
import com.example.kuby.todolist.Task;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.*;

@AllArgsConstructor
@NoArgsConstructor
@Builder
@Entity
@Data
@org.springframework.data.relational.core.mapping.Table(name = "users")
public class UserEntity implements  CustomUserDetails, Serializable {
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
//    @JsonDeserialize(using = LocalDateTimeDeserializer.class)
//    @JsonSerialize(using = LocalDateTimeSerializer.class)
    private LocalDateTime lastActiveDate;
//    @JsonDeserialize(using = LocalDateTimeDeserializer.class)
//    @JsonSerialize(using = LocalDateTimeSerializer.class)
    private LocalDateTime registrationDate;
    @Column(columnDefinition = "BOOLEAN DEFAULT false",nullable = false)
    private boolean isEmailSubmitted;
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private UserRole roles;
    @OneToMany(mappedBy = "creator",fetch = FetchType.LAZY)
    private List<Task> taskList = new ArrayList<>();
    @PrePersist
    public void prePersist() {
        if (provider == null)
            this.provider = Provider.LOCAL;
        if(roles == null)
            this.roles = UserRole.USER;
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
        return new CustomUserPrincipal(this.email,this.provider);
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
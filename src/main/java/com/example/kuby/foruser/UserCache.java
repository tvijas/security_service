package com.example.kuby.foruser;

import com.example.kuby.security.models.enums.UserRoles;
import lombok.AllArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serializable;
import java.util.Collection;
import java.util.List;

@AllArgsConstructor
public class UserCache implements UserDetails, Serializable {
        private String login;
        private String password;
        private UserRoles roles;

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return List.of(new SimpleGrantedAuthority(roles.name()));
        }
        @Override //??????
        public String getUsername() {
                return this.login;
        }
        @Override
        public String getPassword() {
                return this.password;
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
                return true;
        }
}

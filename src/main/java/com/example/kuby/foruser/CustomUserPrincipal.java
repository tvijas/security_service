package com.example.kuby.foruser;

import com.example.kuby.security.models.enums.Provider;

public record CustomUserPrincipal(String email, Provider provider) {
}

package com.example.kuby.security.models.tokens;

import lombok.Getter;

public record TokenPair(
        AccessToken accessToken,
        RefreshToken refreshToken
) {
    public String getAccessTokenValue(){
        return this.accessToken.accessToken();
    }
    public String getRefreshTokenValue(){
        return this.refreshToken.refreshToken();
    }
}

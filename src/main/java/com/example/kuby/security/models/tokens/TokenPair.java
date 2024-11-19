package com.example.kuby.security.models.tokens;

import lombok.Getter;

public record TokenPair(
        AccessToken accessToken,
        RefreshToken refreshToken
) {
    public String getAccessTokenValue(){
        return this.accessToken.getAccessToken();
    }
    public String getRefreshTokenValue(){
        return this.refreshToken.getRefreshToken();
    }
}

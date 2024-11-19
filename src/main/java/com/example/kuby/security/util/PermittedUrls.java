package com.example.kuby.security.util;

import jakarta.servlet.http.HttpServletRequest;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Set;

@Component
public final class PermittedUrls {
    private final Set<RequestMatcher> permitAllMatchers;

    private PermittedUrls(Set<RequestMatcher> permitAllMatchers) {
        this.permitAllMatchers = permitAllMatchers;
    }

    public boolean isPermitAllRequest(HttpServletRequest request) {
        return permitAllMatchers.stream()
                .anyMatch(matcher -> matcher.matches(request));
    }

    public static Builder builder() {
        return new Builder();
    }

    @NoArgsConstructor(access = AccessLevel.PRIVATE)
    public static class Builder {
        private final Set<RequestMatcher> permitAllMatchers = new HashSet<>();

        public Builder addPermitAllMatcher(HttpMethod httpMethod, String pattern) {
            permitAllMatchers.add(new AntPathRequestMatcher(pattern, httpMethod.name()));
            return this;
        }

        public Builder addPermitAllMatcher(String pattern) {
            permitAllMatchers.add(new AntPathRequestMatcher(pattern));
            return this;
        }

        public PermittedUrls build() {
            return new PermittedUrls(new HashSet<>(permitAllMatchers));
        }
    }
}
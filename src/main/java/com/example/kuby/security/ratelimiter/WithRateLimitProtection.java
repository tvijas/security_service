    package com.example.kuby.security.ratelimiter;

    import java.lang.annotation.ElementType;
    import java.lang.annotation.Retention;
    import java.lang.annotation.RetentionPolicy;
    import java.lang.annotation.Target;

    @Retention(RetentionPolicy.RUNTIME)
    @Target(ElementType.METHOD)
    public @interface WithRateLimitProtection {
        int rateLimit() default 5;
        long rateDuration() default 60000;

    }
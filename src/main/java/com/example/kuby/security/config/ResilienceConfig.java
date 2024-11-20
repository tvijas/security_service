package com.example.kuby.security.config;
//
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//
//@Configuration
//public class ResilienceConfig {
//    @Bean
//    public RateLimiterRegistry rateLimiterRegistry() {
//        RateLimiterConfig config = RateLimiterConfig.custom()
//                .limitForPeriod(3)
//                .limitRefreshPeriod(Duration.ofMinutes(1))
//                .timeoutDuration(Duration.ofSeconds(1))
//                .build();
//
//        return RateLimiterRegistry.of(config);
//    }
//}

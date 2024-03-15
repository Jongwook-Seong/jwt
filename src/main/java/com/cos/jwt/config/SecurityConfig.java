package com.cos.jwt.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true, prePostEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsFilter corsFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(CsrfConfigurer::disable);

        /** JWT 서버 셋팅 **/
        http.sessionManagement((sessionManagement) -> sessionManagement
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // STATELESS : 세션을 사용하지 않는다.
                .addFilter(corsFilter); // 인증이 필요 없을 때에는 @CrossOrigin, 인증이 필요할 때는 시큐리티 필터 등록
        http.formLogin((form) -> form.disable());
        http.httpBasic((basic) -> basic.disable()); // 기본 http가 아닌 https 사용(Basic ID/PW X, Bearer Token O)

        http.authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/api/v1/user/**").authenticated()
                        .requestMatchers("/api/v1/manager/**").hasAnyRole("ADMIN", "MANAGER")
                        .requestMatchers("/api/v1/admin/**").hasAnyRole("ADMIN")
                        .anyRequest().permitAll()
        );
        return http.build();
    }
}

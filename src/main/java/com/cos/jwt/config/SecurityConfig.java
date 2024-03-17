package com.cos.jwt.config;

import com.cos.jwt.config.auth.PrincipalDetailsService;
import com.cos.jwt.config.jwt.JwtAuthenticationFilter;
import com.cos.jwt.filter.MyFilter3;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
//@EnableMethodSecurity(securedEnabled = true, prePostEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsFilter corsFilter;
    private final PrincipalDetailsService principalDetailsService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        AuthenticationManagerBuilder sharedObject = http.getSharedObject(AuthenticationManagerBuilder.class);
        sharedObject.userDetailsService(principalDetailsService);
        AuthenticationManager authenticationManager = sharedObject.build();
        http.authenticationManager(authenticationManager);
//        AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);

        http.addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class);
        http.csrf(CsrfConfigurer::disable);

        /** JWT 서버 셋팅 **/
        http.sessionManagement((sessionManagement) -> sessionManagement
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)); // STATELESS : 세션을 사용하지 않는다.
        http.addFilter(corsFilter); // 인증이 필요 없을 때에는 @CrossOrigin, 인증이 필요할 때는 시큐리티 필터 등록
        http.formLogin((form) -> form.disable());
        http.httpBasic((basic) -> basic.disable()); // 기본 http가 아닌 https 사용(Basic ID/PW X, Bearer Token O)
        http.addFilter(new JwtAuthenticationFilter(authenticationManager)); // AuthenticationManager(로그인 시 사용)

        http.authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/user/**").authenticated()
                        .requestMatchers("/manager/**").hasAnyRole("ADMIN", "MANAGER")
                        .requestMatchers("/admin/**").hasAnyRole("ADMIN")
                        .anyRequest().permitAll()
        );
        return http.build();
    }
}

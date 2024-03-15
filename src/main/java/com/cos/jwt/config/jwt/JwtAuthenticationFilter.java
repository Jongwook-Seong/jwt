package com.cos.jwt.config.jwt;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * 스프링 시큐리티에 UsernamePasswordAuthenticationFilter가 있다.
 * /login 요청해서 username, password를 전송하면(POST)
 * UsernamePasswordAuthenticationFilter가 동작한다.
 */
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    // /login 요청을 하면 로그인 시도를 위해 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("로그인 시도: JwtAuthenticationFilter");

        // 1. username, password를 받아서
        // 2. 정상인지 로그인 시도를 해본다.
        // authenticationManager로 로그인 시도를 하면 PrincipalDetailsService가 호출된다.
        // => loadUserByUsername() 실행
        // 3. PrincipalDetails를 세션에 담고(권한 관리 목적)
        // 4. JWT 토큰을 만들어서 응답한다.

        return super.attemptAuthentication(request, response);
    }
}

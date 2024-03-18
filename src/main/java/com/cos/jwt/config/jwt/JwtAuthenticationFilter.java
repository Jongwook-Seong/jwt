package com.cos.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Date;

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
        try {
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println(user);

            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // PrincipalDetailsService.loadUserByUsername() 함수가 실행된다.
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            // username 값이 있다는 것은 로그인이 정상적으로 되었다는 뜻
            System.out.println("로그인 완료: " + principalDetails.getUser().getUsername());
            /**
             * authentication 객체를 session 영역에 저장해야 하고, 그 방법이 return이다.
             * 권한 관리를 security가 대신 해주므로 return을 하는 것은 편하려고 하는 것이다.
             * 굳이 JWT 토큰을 사용하면서 세션을 만들 이유는 없다. 단지 권한 처리 때문에 세션에 넣는 것이다.
             */

            return authentication;
        } catch (IOException e) {
            e.printStackTrace();
        }

        // 2. 정상인지 로그인 시도를 해본다.
        // authenticationManager로 로그인 시도를 하면 PrincipalDetailsService가 호출된다.
        // => loadUserByUsername() 실행
        // 3. PrincipalDetails를 세션에 담고(권한 관리 목적)
        // 4. JWT 토큰을 만들어서 응답한다.

        return null;
    }

    /** attemptAuthentication() 실행 후 인증이 정상적으로 되었으면 successfulAuthentication() 실행 **/
    // JWT 토큰을 만들어서 request 요청한 사용자에게 response 해준다.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult)
            throws IOException, ServletException {
        System.out.println("successfulAuthentication 실행: 인증 완료");
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        String jwtToken = JWT.create()
                .withSubject("cos토큰")
                .withExpiresAt(new Date(System.currentTimeMillis() + JwtProperties.EXPIRATION_TIME))
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512(JwtProperties.SECRET));

        response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX + jwtToken);
    }
}

package com.cos.jwt.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter {

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        /**
         * cos 토큰을 만들어줘야 함.
         * ID, PW가 정상적으로 들어와서 로그인이 완료되면 토큰을 만들어주고 그것에 응답한다.
         * 요청할 때마다 헤더에 Authorization에 value 값으로 토큰을 가지고 온다.
         * 그때 넘어온 토큰이 내가 만든 토큰이 맞는지만 검증하면 된다. (RSA, HS256)
         */
        if (request.getMethod().equals("POST")) {
            System.out.println("POST 요청됨");
            String headerAuth = request.getHeader("Authorization");
            System.out.println(headerAuth);
            System.out.println("필터3");

            // cos라는 토큰이 있다고 가정
            if (headerAuth.equals("cos")) {
                filterChain.doFilter(request, response);
            } else {
                PrintWriter out = response.getWriter();
                out.println("인증 안 됨");
            }
        }
    }
}

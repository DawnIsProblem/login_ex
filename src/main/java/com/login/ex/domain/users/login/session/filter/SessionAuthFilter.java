package com.login.ex.domain.users.login.session.filter;

import com.login.ex.domain.users.login.session.dto.response.SessionResponseDto;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

public class SessionAuthFilter extends OncePerRequestFilter {

    private static final String SESSION_KEY = "LOGIN_USER";

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain
    ) throws ServletException, IOException {
        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            var session = request.getSession(false);
            if (session != null) {
                Object principal = session.getAttribute(SESSION_KEY);
                if (principal instanceof SessionResponseDto responseDto) {
                    var authorities = List.of(new SimpleGrantedAuthority("ROLE_" + responseDto.getRole()));
                    var auth = new UsernamePasswordAuthenticationToken(
                            responseDto.getLoginId(), null, authorities);
                    auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContext context = SecurityContextHolder.createEmptyContext();
                    context.setAuthentication(auth);
                    SecurityContextHolder.setContext(context);
                }
            }
        }
        chain.doFilter(request, response);
    }
}

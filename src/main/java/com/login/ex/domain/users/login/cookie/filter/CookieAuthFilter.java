package com.login.ex.domain.users.login.cookie.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.login.ex.domain.users.login.cookie.util.SignedCookieUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@AllArgsConstructor
public class CookieAuthFilter extends OncePerRequestFilter {

    @Value("${COOKIE_SIGN_SECRET}")
    private String secret;
    @Value("${COOKIE_NAME:AUTH}")
    private String cookieName;

    private final ObjectMapper om = new ObjectMapper();

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        try {
            if (SecurityContextHolder.getContext().getAuthentication() == null) {
                Optional<Cookie> auth = findCookie(req, cookieName);
                if (auth.isPresent()) {
                    String token = auth.get().getValue();
                    var util = new SignedCookieUtil(secret);
                    String json = util.verifyAndExtract(token);
                    Map<String,Object> payload = om.readValue(json, Map.class);

                    long exp = ((Number)payload.get("exp")).longValue();
                    if (Instant.now().getEpochSecond() < exp) {
                        String loginId = (String) payload.get("sub");
                        String role = (String) payload.get("role");
                        var authToken = new UsernamePasswordAuthenticationToken(
                                loginId, null, List.of(new SimpleGrantedAuthority("ROLE_"+role)));
                        SecurityContextHolder.getContext().setAuthentication(authToken);
                    }
                }
            }
        } catch (Exception ignore) {
            // 유효하지 않은 쿠키면 그냥 인증 없이 통과 (필요시 401 리턴하도록 변경 가능)
        }
        chain.doFilter(req, res);
    }

    private Optional<Cookie> findCookie(HttpServletRequest req, String name) {
        if (req.getCookies()==null) return Optional.empty();
        for (Cookie c : req.getCookies()) if (name.equals(c.getName())) return Optional.of(c);
        return Optional.empty();
    }

}
package com.login.ex.common.config;

import com.login.ex.domain.users.login.cookie.filter.CookieAuthFilter;
import com.login.ex.domain.users.login.jwt.filter.JwtAuthenticationFilter;
import com.login.ex.domain.users.login.jwt.util.JwtUtil;
import com.login.ex.domain.users.login.session.filter.SessionAuthFilter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.RequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // CookieAuthFilter를 빈으로 등록
    @Bean
    CookieAuthFilter cookieAuthFilter(
            @Value("${COOKIE_SIGN_SECRET}") String secret,
            @Value("${COOKIE_NAME:AUTH}") String cookieName
    ) {
        return new CookieAuthFilter(secret, cookieName);
    }

    @Bean
    JwtUtil jwtUtil(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.issuer}") String issuer,
            @Value("${jwt.access-ttl-seconds}") long accessTtl,
            @Value("${jwt.refresh-ttl-seconds}") long refreshTtl
    ) {
        return new JwtUtil(secret, issuer, accessTtl, refreshTtl);
    }

    /**
     * 기본 체인: 스웨거/회원가입은 허용, 나머지는 막거나(denyAll) 개발중이면 permitAll
     * 개발 편의로 anyRequest().permitAll()을 쓰면 다른 체인보다 우선순위(@Order) 때문에
     * 실제 매칭은 각 체인이 담당합니다. 필요에 맞게 조절하세요.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, CookieAuthFilter cookieFilter, JwtUtil jwtUtil) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(a -> a
                        .requestMatchers(
                                "/v3/api-docs/**",
                                "/swagger-ui.html",
                                "/swagger-ui/**",
                                "/api/signup",
                                "/login",
                                "/css/**",
                                "/js/**",
                                "/images/**"
                        ).permitAll()
                        .requestMatchers(
                                "/home",
                                "/api/common/me"
                        ).authenticated()
                        .anyRequest().denyAll()
                )
                .formLogin(f -> f.disable())
                .httpBasic(b -> b.disable())
                .addFilterBefore(new SessionAuthFilter(), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(cookieFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(new JwtAuthenticationFilter(jwtUtil), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }


    /**
     * @Order 어노테이션을 사용하여 [세션 - JWT -쿠키] 순으로 필터를 동작시켜서 각각 로그인 방식에 맞는 필터체인에 걸리게 함
     */

    /**
     * 세션 체인: /api/session/** 전용.
     * CSRF는 켜고, 로그인/로그아웃 POST만 예외 처리.
     */
    @Bean
    @Order(1)
    SecurityFilterChain sessionChain(HttpSecurity http) throws Exception {

        // 경로 + 메서드 매칭 (커스텀 RequestMatcher)
        RequestMatcher loginPost = request ->
                "/api/session/login".equals(request.getRequestURI()) &&
                        "POST".equalsIgnoreCase(request.getMethod());

        RequestMatcher logoutPost = request ->
                "/api/session/logout".equals(request.getRequestURI()) &&
                        "POST".equalsIgnoreCase(request.getMethod());

        http.securityMatcher("/api/session/**")
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        // 로그인/로그아웃 POST는 CSRF 토큰 없이 허용
                        .ignoringRequestMatchers(loginPost, logoutPost)
                )
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
                .authorizeHttpRequests(a -> a
                        .requestMatchers(
                                "/api/session/login",
                                "/api/session/logout"
                        ).permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin(f -> f.disable())
                .httpBasic(b -> b.disable())
                .addFilterBefore(new SessionAuthFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * 쿠키 체인: /api/cookie/** 전용.
     * CSRF는 켜고, 로그인/로그아웃 POST만 예외 처리.
     */
    @Bean
    @Order(2)
    SecurityFilterChain cookieChain(HttpSecurity http, CookieAuthFilter cookieFilter) throws Exception {

        // login, logout POST만 CSRF에서 제외
        RequestMatcher cookieLoginPost = req -> "/api/cookie/login".equals(req.getRequestURI()) && "POST".equalsIgnoreCase(req.getMethod());
        RequestMatcher cookieLogoutPost = req -> "/api/cookie/logout".equals(req.getRequestURI()) && "POST".equalsIgnoreCase(req.getMethod());

        http.securityMatcher("/api/cookie/**")
                .csrf(csrf -> csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .ignoringRequestMatchers(cookieLoginPost, cookieLogoutPost)
                )
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(a -> a
                        .requestMatchers("/api/cookie/login", "/api/cookie/logout").permitAll()
                        .anyRequest().authenticated()
                )
                .addFilterBefore(cookieFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * JWT 체인: /api/jwt/** 전용.
     * CSRF는 끄고 stateless상태 유지 및 헤더로 토큰 넘김
     * 갱신은 refresh-token을 사용
     */
    @Bean
    @Order(3)
    SecurityFilterChain jwtChain(HttpSecurity http, JwtUtil jwtUtil) throws Exception {
        http.securityMatcher("/api/jwt/**")
                .csrf(csrf -> csrf.disable()) // 헤더 방식이라면 CSRF 불필요
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(a -> a
                        .requestMatchers("/api/jwt/login", "/api/jwt/refresh").permitAll()
                        .anyRequest().authenticated()
                )
                .addFilterBefore(new JwtAuthenticationFilter(jwtUtil), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }


}


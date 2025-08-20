package com.login.ex.domain.users.login.jwt.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

public class JwtUtil {

    private final Key key;
    private final String issuer;
    private final long accessTtlSec;
    private final long refreshTtlSec;

    public JwtUtil(String secret, String issuer, long accessTtlSec, long refreshTtlSec) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.issuer = issuer;
        this.accessTtlSec = accessTtlSec;
        this.refreshTtlSec = refreshTtlSec;
    }

    public String createAccessToken(String subject, String role, String nickname) {
        long now = Instant.now().getEpochSecond();
        return Jwts.builder()
                .setHeaderParam(Header.TYPE, Header.JWT_TYPE)
                .setIssuer(issuer)
                .setSubject(subject) // 보통 loginId
                .addClaims(Map.of(
                        "role", role,
                        "nickname", nickname
                ))
                .setIssuedAt(new Date(now * 1000))
                .setExpiration(new Date((now + accessTtlSec) * 1000))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public String createRefreshToken(String subject) {
        long now = Instant.now().getEpochSecond();
        return Jwts.builder()
                .setHeaderParam(Header.TYPE, Header.JWT_TYPE)
                .setIssuer(issuer)
                .setSubject(subject)
                .setIssuedAt(new Date(now * 1000))
                .setExpiration(new Date((now + refreshTtlSec) * 1000))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public Jws<Claims> parse(String token) {
        return Jwts.parserBuilder().setSigningKey(key).requireIssuer(issuer).build().parseClaimsJws(token);
    }

    public boolean isExpired(Jws<Claims> jws) {
        return jws.getBody().getExpiration().before(new Date());
    }

}

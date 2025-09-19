package com.aws.compass.jwt;

import com.aws.compass.entity.User;
import com.aws.compass.repository.AuthMapper;
import com.aws.compass.security.PrincipalUser;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;

@Slf4j
@Component
public class JwtProvider {

    private final Key key;
    private final AuthMapper authMapper;

    // 만료시간(기본값): Access 24h, Refresh 14d
    private final long ACCESS_TOKEN_EXPIRE_MS  = 1000L * 60 * 60 * 24;
    private final long REFRESH_TOKEN_EXPIRE_MS = 1000L * 60 * 60 * 24 * 14;

    public JwtProvider(
            @Value("${jwt.secret}") String secret,
            @Autowired AuthMapper authMapper
    ) {
        this.key = buildKey(secret);
        this.authMapper = authMapper;
    }

    /** secret이 Base64일 수도/아닐 수도 있는 상황을 안전하게 처리 */
    private Key buildKey(String secret) {
        try {
            // Base64로 인코딩된 키를 우선 시도
            byte[] decoded = Decoders.BASE64.decode(secret);
            return Keys.hmacShaKeyFor(decoded);
        } catch (IllegalArgumentException e) {
            // Base64가 아니면 평문 바이트로 키 생성
            byte[] raw = secret.getBytes(StandardCharsets.UTF_8);
            return Keys.hmacShaKeyFor(raw);
        }
    }

    /** 기존 Authentication 기반(필요 시 유지) */
    public String generateToken(Authentication authentication) {
        PrincipalUser principalUser = (PrincipalUser) authentication.getPrincipal();
        User user = principalUser.getUser();
        return generateAccessToken(user);
    }

    /** AccessToken 생성 */
    public String generateAccessToken(User user) {
        Date exp = new Date(System.currentTimeMillis() + ACCESS_TOKEN_EXPIRE_MS);

        return Jwts.builder()
                .setSubject("AccessToken")
                .setExpiration(exp)
                // 식별자: oauth2Id가 있으면 소셜 기준, 없으면 이메일 기준
                .claim("oauth2Id", user.getOauth2Id())
                .claim("email",    user.getEmail())
                .claim("userId",   user.getUserId())
                .claim("provider", user.getProvider())
                .claim("roleId",   user.getRoleId())
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    /** RefreshToken 생성(필요 없으면 호출하지 않아도 됨) */
    public String generateRefreshToken(User user) {
        Date exp = new Date(System.currentTimeMillis() + REFRESH_TOKEN_EXPIRE_MS);

        return Jwts.builder()
                .setSubject("RefreshToken")
                .setExpiration(exp)
                .claim("userId",   user.getUserId())
                .claim("provider", user.getProvider())
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    /** 메일 인증 토큰(5분 유효) */
    public String generateAuthMailToken(String email) {
        Date exp = new Date(System.currentTimeMillis() + 1000 * 60 * 5);

        return Jwts.builder()
                .setSubject("AuthenticationEmailToken")
                .setExpiration(exp)
                .claim("email", email)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    /** Bearer 토큰에서 실제 토큰 추출 */
    public String getToken(String authorizationHeader) {
        if (!StringUtils.hasText(authorizationHeader)) return null;
        String prefix = "Bearer ";
        if (authorizationHeader.startsWith(prefix)) {
            return authorizationHeader.substring(prefix.length());
        }
        return null;
    }

    /** Claims 파싱 */
    public Claims getClaims(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (Exception e) {
            log.warn("JWT parse error: {} - {}", e.getClass().getSimpleName(), e.getMessage());
            return null;
        }
    }

    /** 토큰 → Authentication (SecurityContext 용) */
    public Authentication getAuthentication(String token) {
        Claims claims = getClaims(token);
        if (claims == null) return null;

        // oauth2Id 우선, 없으면 email 기준 조회
        User user = null;
        Object oauth2IdClaim = claims.get("oauth2Id");
        if (oauth2IdClaim != null && StringUtils.hasText(String.valueOf(oauth2IdClaim))) {
            user = authMapper.findUserByOauth2Id(String.valueOf(oauth2IdClaim));
        } else {
            Object emailClaim = claims.get("email");
            if (emailClaim != null && StringUtils.hasText(String.valueOf(emailClaim))) {
                user = authMapper.findUserByEmail(String.valueOf(emailClaim));
            }
        }
        if (user == null) return null;

        PrincipalUser principalUser = new PrincipalUser(user);
        return new UsernamePasswordAuthenticationToken(
                principalUser, null, principalUser.getAuthorities());
    }

    /** 프론트 응답용: Access 만료(초) */
    public long getAccessTokenExpirySeconds() {
        return ACCESS_TOKEN_EXPIRE_MS / 1000;
    }
}

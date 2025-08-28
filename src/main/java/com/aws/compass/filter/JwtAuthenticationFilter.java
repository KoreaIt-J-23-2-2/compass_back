package com.aws.compass.filter;

import com.aws.compass.jwt.JwtProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtProvider jwtProvider;
    private static final AntPathMatcher PATH_MATCHER = new AntPathMatcher();

    /** 공개 경로는 필터 제외 */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String uri = request.getRequestURI();
        return PATH_MATCHER.match("/api/auth/**", uri)
                || PATH_MATCHER.match("/oauth2/**", uri)
                || "/error".equals(uri)
                || "/favicon.ico".equals(uri);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {

        String bearer = request.getHeader("Authorization");

        // JwtProvider에 resolveToken이 있다면 이걸 사용하세요.
        // (기존 getToken만 있다면 getToken으로 교체하거나, JwtProvider에 bridge 메서드 추가)
        String token = null;
        try {
            token = jwtProvider.getToken(bearer);
        } catch (NoSuchMethodError | Exception ignore) {
            // resolveToken이 없다면 getToken 사용 (브리지)
            try { token = jwtProvider.getToken(bearer); } catch (Exception ignored) {}
        }

        if (token != null && !token.isEmpty()) {
            Authentication authentication = jwtProvider.getAuthentication(token);
            if (authentication != null) {
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }

        // ⚠️ 여기서 401을 직접 보내지 않습니다.
        // 인증이 필요한 URL인데 인증이 없으면, 이후 Security에서 entryPoint로 401 처리합니다.
        chain.doFilter(request, response);
    }
}

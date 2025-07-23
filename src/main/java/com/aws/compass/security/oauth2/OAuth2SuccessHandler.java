package com.aws.compass.security.oauth2;

import com.aws.compass.entity.User;
import com.aws.compass.jwt.JwtProvider;
import com.aws.compass.repository.AuthMapper;
import com.aws.compass.security.PrincipalUser;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    @Value("${server.frontAddress}")
    private String frontAddress;

    private final AuthMapper authMapper;
    private final JwtProvider jwtProvider;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        String oauth2Id = authentication.getName(); // PrincipalUserDetailsService의 loadUser에서 return 했던 DefaultOAuth2User의 key값
        User user = authMapper.findUserByOauth2Id(oauth2Id);

        if (user == null) { // 소셜 로그인 돼있는 유저가 없다면 -> 새로 회원가입
            DefaultOAuth2User defaultOAuth2User = (DefaultOAuth2User) authentication.getPrincipal();
            String provider = defaultOAuth2User.getAttributes().get("provider").toString();

            // 회원가입이 안 되었을 때 OAuth2 계정 회원가입 페이지로 이동
            response.sendRedirect(frontAddress + "/auth/detail/signup" +
                    "?oauth2Id=" + oauth2Id +
                    "&provider=" + provider);
            return;
        }
        // 소셜 로그인 돼있는 유저가 있다면 -> 로그인
        PrincipalUser principalUser = new PrincipalUser(user);
        UsernamePasswordAuthenticationToken authenticationToken
                = new UsernamePasswordAuthenticationToken(principalUser, null, principalUser.getAuthorities());
        String accessToken = jwtProvider.generateToken(authenticationToken);
        System.out.println("ACCESS TOKEN: " + accessToken); // 디버깅용
        response.sendRedirect(frontAddress + "/auth/oauth2/signin" +  // client로 token을 보낸다
                "?token=" + URLEncoder.encode(accessToken, "UTF-8"));
    }
}

package com.aws.compass.service;

import com.aws.compass.dto.auth.Oauth2SignupReqDto;
import com.aws.compass.dto.auth.SigninReqDto;
import com.aws.compass.dto.auth.SignupReqDto;
import com.aws.compass.dto.auth.TokenRespDto;
import com.aws.compass.entity.User;
import com.aws.compass.exception.DuplicateException;
import com.aws.compass.repository.AuthMapper;
import com.aws.compass.jwt.JwtProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthMapper authMapper;
    private final PasswordEncoder passwordEncoder; // BCrypt
    private final JwtProvider jwtProvider;
    private final FirebaseService firebaseService;

    /** 일반 회원가입 */
    public boolean signup(SignupReqDto dto) {
        // 이메일/닉네임 중복 체크
        int dup = authMapper.checkDuplicateByEmailAndNickname(dto.getEmail(), dto.getNickname());
        if (dup > 0) {
            responseDuplicateError(dup);
        }

        // 비밀번호 해시
        String encoded = passwordEncoder.encode(dto.getPassword());

        // 저장 (provider는 "LOCAL", enabled는 0으로 시작)
        User user = User.builder()
                .email(dto.getEmail())
                .password(encoded)
                .name(dto.getName())
                .nickname(dto.getNickname())
                .phone(dto.getPhone())
                .provider("LOCAL")
                .enabled(0)
                .roleId(1)
                .build();

        return authMapper.saveLocalUser(user) > 0;
    }

    /** 일반 로그인 */
    public TokenRespDto signin(SigninReqDto dto) {
        User user = authMapper.findUserByEmail(dto.getEmail());
        if (user == null || user.getPassword() == null) {
            throw new BadCredentialsException("이메일 또는 비밀번호가 올바르지 않습니다.");
        }
        if (!passwordEncoder.matches(dto.getPassword(), user.getPassword())) {
            throw new BadCredentialsException("이메일 또는 비밀번호가 올바르지 않습니다.");
        }

        // JWT 발급
        String accessToken = jwtProvider.generateAccessToken(user);    // 프로젝트 메서드명에 맞춰 사용
        String refreshToken = jwtProvider.generateRefreshToken(user);  // 필요 없으면 null 반환하도록 처리 가능
        long expiresIn = jwtProvider.getAccessTokenExpirySeconds();    // 선택

        // Firebase Custom Token 발급
        String firebaseUid = "user_" + user.getUserId();
        String firebaseToken = firebaseService.createCustomToken(firebaseUid);

        return new TokenRespDto("Bearer", accessToken, refreshToken, expiresIn, firebaseToken);
    }

    /** OAuth2 로그인 후 추가정보 입력(프로필 완료) */
    public boolean oauth2Signup(Oauth2SignupReqDto dto) {
        // 존재하는 OAuth2 사용자 확인
        User exists = authMapper.findUserByOauth2Id(dto.getOauth2Id());
        if (exists == null) {
            throw new IllegalArgumentException("존재하지 않는 OAuth2 사용자입니다.");
        }

        // 닉네임 중복(자기 자신 제외) 체크
        int dupNick = authMapper.checkDuplicateByNicknameExcludingUser(dto.getNickname(), exists.getUserId());
        if (dupNick > 0) {
            responseDuplicateError(2); // 닉네임 중복
        }

        // 추가정보 업데이트
        return authMapper.updateUserExtraByOauth2Id(dto) > 0;
    }

    /** 중복 에러 공통 처리 */
    public void responseDuplicateError(int code) {
        Map<String, String> errors = new HashMap<>();
        switch (code) {
            case 1: errors.put("email", "이미 사용중인 이메일입니다."); break;
            case 2: errors.put("nickname", "이미 사용중인 닉네임입니다."); break;
            case 3:
                errors.put("email", "이미 사용중인 이메일입니다.");
                errors.put("nickname", "이미 사용중인 닉네임입니다.");
                break;
        }
        throw new DuplicateException(errors);
    }
}

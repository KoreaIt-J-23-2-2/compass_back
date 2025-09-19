package com.aws.compass.controller;

import com.aws.compass.aop.annotation.ValidAop;
import com.aws.compass.dto.auth.SigninReqDto;
import com.aws.compass.dto.auth.SignupReqDto;
import com.aws.compass.dto.auth.Oauth2SignupReqDto;
import com.aws.compass.dto.auth.TokenRespDto;
import com.aws.compass.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    /** 일반 회원가입 */
    @ValidAop
    @PostMapping("/signup")
    public ResponseEntity<?> signup(
            @Valid @RequestBody SignupReqDto signupReqDto,
            BindingResult bindingResult) {
        return ResponseEntity.ok(authService.signup(signupReqDto));
    }

    /** 일반 로그인 */
    @ValidAop
    @PostMapping("/signin")
    public ResponseEntity<TokenRespDto> signin(
            @Valid @RequestBody SigninReqDto signinReqDto,
            BindingResult bindingResult) {
        return ResponseEntity.ok(authService.signin(signinReqDto));
    }

    /** OAuth2 로그인 후 추가 정보 입력(프로필 완료) */
    @ValidAop
    @PostMapping("/oauth2/signup")
    public ResponseEntity<?> oauth2Signup(
            @Valid @RequestBody Oauth2SignupReqDto reqDto,
            BindingResult bindingResult) {
        return ResponseEntity.ok(authService.oauth2Signup(reqDto));
    }
}

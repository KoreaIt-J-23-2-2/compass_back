package com.aws.compass.dto.auth;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class TokenRespDto {
    private String tokenType;   // 예: "Bearer"
    private String accessToken;
    private String refreshToken; // 필요 없으면 null 가능
    private long expiresIn;     // 만료 시간(초)
    private String firebaseToken;
}

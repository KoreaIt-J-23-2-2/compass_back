package com.aws.compass.dto;

import lombok.Builder;
import lombok.Data;

import javax.validation.constraints.NotBlank;

@Builder
@Data
public class PrincipalRespDto { // 마이페이지에서 쓸 정보들 응답 dto

    private int userId;
    private String email;
    private String password;
    private String oauth2Id;
    private String name;
    private String nickname;
    private String phone;
    private String provider;
    private boolean enabled;
    private int roleId;
}

package com.aws.compass.entity;

import com.aws.compass.dto.PrincipalRespDto;
import lombok.*;

@Builder
@NoArgsConstructor
@AllArgsConstructor
@Data
public class User {
    private int userId;
    private String email;
    private String password;
    private String oauth2Id;
    private String name;
    private String nickname;
    private String phone;
    private String provider;
    private int enabled;
    private int roleId;

    public PrincipalRespDto toPrincipalDto() {
        System.out.println(roleId);
        return PrincipalRespDto.builder()
                .userId(userId)
                .email(email)
                .password(password)
                .oauth2Id(oauth2Id)
                .name(name)
                .nickname(nickname)
                .phone(phone)
                .provider(provider)
                .enabled(enabled > 0)
                .roleId(roleId)
                .build();
    }
}

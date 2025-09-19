package com.aws.compass.repository;

import com.aws.compass.dto.auth.Oauth2SignupReqDto;
import com.aws.compass.entity.User;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface AuthMapper {
    public User findUserByOauth2Id(String oauth2Id);
    public int saveUser(User user);
    // 회원 저장
    int saveLocalUser(User user); // email, password, name, nickname, phone, provider="LOCAL", enabled, role_id

    // 조회
    User findUserByEmail(String email);

    // 업데이트
    int updateUserExtraByOauth2Id(Oauth2SignupReqDto dto);

    // 중복 체크
    int checkDuplicateByEmailAndNickname(String email, String nickname); // email중복=1, nickname중복=2, 둘다=3
    int checkDuplicateByNicknameExcludingUser(String nickname, int userId);
}

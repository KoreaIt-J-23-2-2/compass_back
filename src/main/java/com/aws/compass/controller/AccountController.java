package com.aws.compass.controller;

import com.aws.compass.aop.annotation.ValidAop;
import com.aws.compass.dto.AcademyLikeRespDto;
import com.aws.compass.dto.EditUserReqDto;
import com.aws.compass.dto.PrincipalRespDto;
import com.aws.compass.entity.User;
import com.aws.compass.security.PrincipalUser;
import com.aws.compass.service.AccountService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RestController
@RequiredArgsConstructor
public class AccountController {

    private final AccountService accountService;

    // 로그인 한 유저 정보 들고오기
    @GetMapping("/api/account/principal")
    public ResponseEntity<?> getPrincipal() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // 인증되지 않은 경우
        if (authentication == null || !authentication.isAuthenticated()
            || authentication.getPrincipal().equals("anonymousUser")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build(); // 401
        }
        PrincipalUser principalUser = (PrincipalUser) authentication.getPrincipal();
        return ResponseEntity.ok(principalUser.getUser().toPrincipalDto());
    }

    // 개인 정보 수정
    @ValidAop
    @PutMapping("/api/account/user/{userId}")
    public ResponseEntity<?> editUser(@PathVariable int userId,
                                      @Valid @RequestBody EditUserReqDto editUserReqDto,
                                      BindingResult bindingResult) {
        return ResponseEntity.ok(accountService.updateUser(userId,editUserReqDto));
    }

    // 이메일 인증하기
    @PostMapping("/api/account/auth/email")
    public ResponseEntity<?> sendAuthenticationMail() {
        return ResponseEntity.ok(accountService.sendAuthMail());
    }

    // 인증된 이메일 가져오기
    @GetMapping("/api/account/auth/email")
    public ResponseEntity<?> authenticateMail (String token) {
        //주소의 토큰을 받고 유효한지 확인
        return ResponseEntity.ok(accountService.authenticateMail(token) ? "인증 완료" : "인증 실패");
    }

    // 좋아요 상태
    @GetMapping("/api/account/like/{academyId}/{userId}")
    public ResponseEntity<?> getLikeState (@PathVariable int userId, @PathVariable int academyId) {
        return ResponseEntity.ok(accountService.getLikeState(userId, academyId));
    }

    // 좋아요 추가
    @PostMapping("/api/account/like/{academyId}/{userId}")
    public ResponseEntity<?> setLike(@PathVariable int userId, @PathVariable int academyId) {
        return ResponseEntity.ok(accountService.setLike(userId, academyId));
    }

    // 좋아요 삭제
    @DeleteMapping("/api/account/like/{academyId}/{userId}")
    public ResponseEntity<?> cancelLike(@PathVariable int userId, @PathVariable int academyId) {
        return ResponseEntity.ok(accountService.cancelLike(userId, academyId));
    }

    // 좋아요 COUNT
    @GetMapping("/api/account/mypage/like/count/{userId}")
    public ResponseEntity<?> getLikeCount(@PathVariable int userId) {
        return ResponseEntity.ok(accountService.getLikeCount(userId));
    }

    // 관심 학원
    @GetMapping("/api/account/mypage/like/{userId}/{page}")
    public ResponseEntity<?> getLikeAcademies(@PathVariable int userId, @PathVariable int page) {
        return ResponseEntity.ok(accountService.getLikeAcademy(userId, page));
    }

    // 관심학원 COUNT
    @GetMapping("/api/account/info/like/count/{academyId}")
    public ResponseEntity<?> getLikeCountOfInfo(@PathVariable int academyId) {
        return ResponseEntity.ok(accountService.getLikeInfoCount(academyId));
    }

    @GetMapping("/api/account/{userId}/reviews/{page}")
    public ResponseEntity<?> getUserReviews(@PathVariable int userId, @PathVariable int page) {
        return ResponseEntity.ok(accountService.getUserReviews(userId, page));
    }

    @DeleteMapping("/api/account/{userId}")
    public ResponseEntity<?> deleteUser(@PathVariable int userId){
        return ResponseEntity.ok(accountService.deleteUser(userId));
    }
}

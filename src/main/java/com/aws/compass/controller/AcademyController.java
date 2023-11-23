package com.aws.compass.controller;

import com.aws.compass.aop.annotation.ValidAop;
import com.aws.compass.dto.AcademyRegistrationReqDto;
import com.aws.compass.dto.ReviewReqDto;
import com.aws.compass.dto.SearchAcademysReqDto;
import com.aws.compass.dto.EditAcademyInfoReqDto;
import com.aws.compass.service.AcademyService;
import lombok.RequiredArgsConstructor;
import org.aspectj.apache.bcel.generic.ClassGen;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RestController
@RequiredArgsConstructor
public class AcademyController {

    private final AcademyService academyService;

    //학원 전체 리스트 가져오기
    @GetMapping("/api/academies")
    public ResponseEntity<?> getAcademies(SearchAcademysReqDto searchAcademysReqDto) {
        System.out.println(searchAcademysReqDto);
        return ResponseEntity.ok(academyService.getAcademies(searchAcademysReqDto));
    }

    //학원 정보 가져오기 (단건)
    @GetMapping("/api/academy")
    public ResponseEntity<?> getAcademy(SearchAcademysReqDto searchAcademysReqDto) {
        return ResponseEntity.ok(academyService.getAcademy(searchAcademysReqDto.getACADEMY_ID()));
    }

    //학원 등록하기
    @ValidAop
    @PostMapping("/api/academy")
    public ResponseEntity<?> getAcademyRegist(@Valid @RequestBody AcademyRegistrationReqDto academyRegistrationReqDto, BindingResult bindingResult) {
        return ResponseEntity.ok(academyService.academyRegist(academyRegistrationReqDto));
    }

    @ValidAop
    @PutMapping("/api/academy/{academyRegistrationId}")
    public ResponseEntity<?> updateAcademyRegist(@PathVariable int academyRegistrationId, @Valid @RequestBody AcademyRegistrationReqDto academyRegistrationReqDto, BindingResult bindingResult) {
        return ResponseEntity.ok(academyService.updateAcademyRegist(academyRegistrationId, academyRegistrationReqDto));
    }

    @GetMapping("/api/academies/applied/{userId}/{page}")
    public ResponseEntity<?> getAppliedAcademies(@PathVariable int userId, @PathVariable int page) {
        return ResponseEntity.ok(academyService.getAppliedAcademies(userId, page));
    }

    @GetMapping("/api/academies/{userId}/{page}")
    public ResponseEntity<?> getMyAcademies(@PathVariable int userId, @PathVariable int page) {
        return ResponseEntity.ok(academyService.getMyAcademies(userId, page));
    }

    @GetMapping("/api/academies/{userId}")
    public ResponseEntity<?> getMyAcademyNames(@PathVariable int userId) {
        return ResponseEntity.ok(academyService.getMyAcademyNames(userId));
    }

    //상세페이지 - 후기 가져오기
    @GetMapping("/api/academy/{academyId}/reviews")
    public ResponseEntity<?> getAcademyReviews(@PathVariable int academyId) {
        return ResponseEntity.ok(academyService.getAcademyReviews(academyId));
    }

    @GetMapping("/api/academy/check/{academyId}")
    public ResponseEntity<?> isAcademyAdminRegistered(@PathVariable int academyId) {
        return ResponseEntity.ok(academyService.isAcademyRegistered(academyId));
    }

    @PutMapping("/api/academy")
    public ResponseEntity<?> editAcademyInfo(@RequestBody EditAcademyInfoReqDto editAcademyInfoReqDto) {
        return ResponseEntity.ok(academyService.editAcademyInfo(editAcademyInfoReqDto));
    }

    @PostMapping("/api/academyInfo/{ACADEMY_ID}")
    public ResponseEntity<?> addAcademyInfo(@RequestBody EditAcademyInfoReqDto editAcademyInfoReqDto) {
        return ResponseEntity.ok(academyService.addAcademyInfo(editAcademyInfoReqDto));
    }

    //상세페이지 - 후기 쓰기
    @PostMapping("/api/review")
    public ResponseEntity<?> writeReview(@RequestBody ReviewReqDto reviewReqDto) {
        return ResponseEntity.ok(academyService.writeReview(reviewReqDto));

    }
  
    //상세페이지 - 내 후기 수정버튼 클릭 시 가져오기
    @GetMapping("/api/review/{academyId}/{userId}")
    public ResponseEntity<?> getMyReview(@PathVariable int academyId, @PathVariable int userId) {
        System.out.println(academyId + userId);
        return ResponseEntity.ok(academyService.getMyReview(academyId, userId));
    }

    //상세페이지 - 후기 수정
    @PutMapping("/api/review")
    public ResponseEntity<?> modifyReview(@RequestBody ReviewReqDto reviewReqDto) {
        return ResponseEntity.ok(academyService.modifyReview(reviewReqDto));
    }

    //상세페이지 - 후기 삭제
    @DeleteMapping("/api/review/{academyId}/{userId}")
    public ResponseEntity<?> deleteReview(@PathVariable int academyId, @PathVariable int userId) {
        return ResponseEntity.ok(academyService.deleteReview(academyId, userId));
    }
}

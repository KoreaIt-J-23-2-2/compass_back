package com.aws.compass.controller;

import com.aws.compass.dto.WriteInquiryAnswerReqDto;
import com.aws.compass.dto.WriteInquiryReqDto;
import com.aws.compass.entity.AcademyInquiryReqDto;
import com.aws.compass.service.InquiryService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RestController
@RequiredArgsConstructor
public class InquiryController {

    private final InquiryService inquiryService;

    // 문의 작성
    @PostMapping("/api/inquiry")
    public ResponseEntity<?> writeInquiry(@Valid @RequestBody WriteInquiryReqDto inquiryReqDto, BindingResult bindingResult) {
        return ResponseEntity.ok(inquiryService.writeInquiry(inquiryReqDto));
    }

    // 사용자(학생)가 작성한 후기 가져오기
    @GetMapping("/api/student/inquiries/{userId}/{page}")
    public ResponseEntity<?> getUserInquiryList(@PathVariable int userId,
                                                @PathVariable int page) {
        return ResponseEntity.ok(inquiryService.getUserInquiries(userId, page));
    }

    // 등록된 학원의 문의 가져오기
    @GetMapping("/api/academy/inquiries")
    public ResponseEntity<?> getInquiryList(AcademyInquiryReqDto inquiryReqDto) {
        System.out.println(inquiryReqDto);
        return ResponseEntity.ok(inquiryService.getInquiryList(inquiryReqDto));
    }

    // 문의 답변 작성
    @PutMapping("/api/inquiry/{inquiryId}/answer")
    public ResponseEntity<?> writeInquiryAnswer(@PathVariable int inquiryId,
                                                @Valid @RequestBody WriteInquiryAnswerReqDto inquiryAnswerReqDto,
                                                BindingResult bindingResult) {
        return ResponseEntity.ok(inquiryService.writeInquiryAnswer(inquiryId, inquiryAnswerReqDto));
    }

    // 답변이 달린 문의 표시
    @PutMapping("/api/inquiry/{inquiryId}/updateAnswerChecked")
    public ResponseEntity<?> updateAnswerChecked(@PathVariable int inquiryId, @RequestParam int answerChecked) {
        return ResponseEntity.ok(inquiryService.updateAnswerChecked(inquiryId, answerChecked));
    }

    // 답이 달렸지만 확인하지 않은 문의 수 가져오기
    @GetMapping("/api/inquiry/{userId}/UncheckedAnswerCount")
    public ResponseEntity<?> getUncheckedAnswerCount(@PathVariable int userId) {
        return ResponseEntity.ok(inquiryService.getuncheckedAnswerCount(userId));
    }

}

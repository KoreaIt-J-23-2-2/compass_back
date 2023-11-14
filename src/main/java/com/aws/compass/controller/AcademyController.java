package com.aws.compass.controller;

import com.aws.compass.aop.annotation.ValidAop;
import com.aws.compass.dto.AcademyRegistrationReqDto;
import com.aws.compass.dto.SearchAcademysReqDto;
import com.aws.compass.service.AcademyService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
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
        System.out.println(searchAcademysReqDto);
        return ResponseEntity.ok(academyService.getAcademy(searchAcademysReqDto));
    }

    //학원 상세 정보 가져오기(단건)
    @GetMapping("")

    @ValidAop
    @PostMapping("/api/academy")
    public ResponseEntity<?> getAcademyRegist(@Valid @RequestBody AcademyRegistrationReqDto academyRegistrationReqDto, BindingResult bindingResult) {
        System.out.println(academyService.academyRegist(academyRegistrationReqDto));
        return ResponseEntity.ok(academyService.academyRegist(academyRegistrationReqDto));
    }
}

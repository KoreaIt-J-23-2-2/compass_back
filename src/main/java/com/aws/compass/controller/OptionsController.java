package com.aws.compass.controller;

import com.aws.compass.service.OptionService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/option")
public class OptionsController {

    private final OptionService optionService;

    @GetMapping("/education-offices")
    public ResponseEntity<?> getEducationOffices() {
        return ResponseEntity.ok(optionService.getEducationOfficeList());
    }

    @GetMapping("/administrative-districts")
    public ResponseEntity<?> getAdministrativeDistrict() {
        return  ResponseEntity.ok(optionService.getAdministrativeDistrictList());
    }

    @GetMapping("/categories")
    public ResponseEntity<?> getCategories() {
        return  ResponseEntity.ok(optionService.getCategoryList());
    }

    @GetMapping("/category-details")
    public ResponseEntity<?> getCategoryDetails() {
        return  ResponseEntity.ok(optionService.getCategoryDetailList());
    }


}

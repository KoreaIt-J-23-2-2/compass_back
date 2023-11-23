package com.aws.compass.controller;

import com.aws.compass.service.AdvertisementService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class AdvertisementController {

    private final AdvertisementService advertisementService;

    @GetMapping("/api/ad/academies/random")
    public ResponseEntity<?> getRandomAcademies() {
        return ResponseEntity.ok(advertisementService.getADOfRandomAcademies());
    }


}

package com.aws.compass.service;

import com.aws.compass.entity.Academy;
import com.aws.compass.repository.AdvertisementMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class AdvertisementService {
    private final AdvertisementMapper advertisementMapper;

    public List<Academy> getADOfRandomAcademies() {
        return advertisementMapper.getADOfRandomAcademies();
    }
}

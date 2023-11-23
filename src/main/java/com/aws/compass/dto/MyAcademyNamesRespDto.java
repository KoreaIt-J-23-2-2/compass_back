package com.aws.compass.dto;

import com.aws.compass.entity.Academy;
import com.aws.compass.entity.AcademyRegistration;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
@AllArgsConstructor
public class MyAcademyNamesRespDto {
    private int academyId;
    private String acaNm;
}

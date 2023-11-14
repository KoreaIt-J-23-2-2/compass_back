package com.aws.compass.dto;

import com.aws.compass.entity.AcademyRegistration;
import lombok.Builder;
import lombok.Data;

@Data
public class AcademyRegistrationReqDto {
    private int academyId;
    private String match;
    private int userId;
    private String businessRegistrationFile;
    private String idFile;
    private String operationRegistrationFile;

    public AcademyRegistration toAcademyRegist() {
        return AcademyRegistration.builder()
                .academyId(academyId)
                .match(match)
                .userId(userId)
                .businessRegistrationFile(businessRegistrationFile)
                .idFile(idFile)
                .operationRegistrationFile(operationRegistrationFile)
                .build();
    }
}

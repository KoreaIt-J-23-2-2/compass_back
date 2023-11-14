package com.aws.compass.dto;

import lombok.Builder;
import lombok.Data;

@Builder
@Data
public class AwaitingAcademiesRepDto {
    private int academyRegistrationId;
    private int academyId;
    private String acaAsnum;
    private String acaNm;
    private String admstZoneNm;
    private String match;
    private int userId;
    private String name;
    private String businessRegistrationFile;
    private String idFile;
    private String operationRegistrationFile;
}

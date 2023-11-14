package com.aws.compass.dto;

import lombok.Builder;
import lombok.Data;

@Builder
@Data
public class AdministrativeDistrictRespDto { // 정보등록 응답 데이터 DTO
    private int administrativeDistrictId;
    private String  educationOfficeCode;
    private String administrativeDistrictName;
}

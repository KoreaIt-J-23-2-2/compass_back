package com.aws.compass.entity;

import com.aws.compass.dto.AdministrativeDistrictRespDto;
import com.aws.compass.dto.EducationOfficeRespDto;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@NoArgsConstructor
@AllArgsConstructor
@Data
public class AdministrativeDistrict {
    private int administrativeDistrictId;
    private String  educationOfficeCode;
    private String administrativeDistrictName;

    public AdministrativeDistrictRespDto toAdministrativeDistrictDto() {
        return AdministrativeDistrictRespDto.builder()
                .administrativeDistrictId(administrativeDistrictId)
                .educationOfficeCode(educationOfficeCode)
                .administrativeDistrictName(administrativeDistrictName)
                .build();
    }
}

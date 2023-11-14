package com.aws.compass.entity;

import com.aws.compass.dto.AwaitingAcademiesRepDto;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@NoArgsConstructor
@AllArgsConstructor
@Data
public class AcademyRegistration {
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
    private int approvalStatus;

    public AwaitingAcademiesRepDto toAwaitingAcademiesDto() {
        return AwaitingAcademiesRepDto.builder()
                .academyRegistrationId(academyRegistrationId)
                .academyId(academyId)
                .acaAsnum(acaAsnum)
                .acaNm(acaNm)
                .admstZoneNm(admstZoneNm)
                .match(match)
                .userId(userId)
                .name(name)
                .businessRegistrationFile(businessRegistrationFile)
                .idFile(idFile)
                .operationRegistrationFile(operationRegistrationFile)
                .build();
    }

}

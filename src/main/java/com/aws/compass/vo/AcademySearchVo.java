package com.aws.compass.vo;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@NoArgsConstructor
@AllArgsConstructor
@Data
public class AcademySearchVo {
    private int academyId;
    private String atptOfcdcScCode;
    private String admstZoneNm;
    private String acaAsnum;
    private String acaNm;
    private String realmScNm;
    private String leOrdNm;
    private String leCrseNm;
    private int index;
    private int pSize;
}

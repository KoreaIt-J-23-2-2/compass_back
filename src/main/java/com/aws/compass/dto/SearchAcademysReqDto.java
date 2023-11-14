package com.aws.compass.dto;

import com.aws.compass.vo.AcademySearchVo;
import lombok.Data;

@Data
public class SearchAcademysReqDto {
    private int ACADEMY_ID;
    private int pIndex;
    private int pSize;
    private String ATPT_OFCDC_SC_CODE;
    private String ADMST_ZONE_NM;
    private String ACA_ASNUM;
    private String ACA_NM;
    private String REALM_SC_NM;
    private String LE_ORD_NM;
    private String LE_CRSE_NM;

    public AcademySearchVo toVo() {
        return AcademySearchVo.builder()
                .index((pIndex - 1) * pSize)
                .pSize(pSize)
                .atptOfcdcScCode(ATPT_OFCDC_SC_CODE)
                .admstZoneNm(ADMST_ZONE_NM)
                .acaAsnum(ACA_ASNUM)
                .acaNm(ACA_NM)
                .realmScNm(REALM_SC_NM)
                .leOrdNm(LE_ORD_NM)
                .leCrseNm(LE_CRSE_NM)
                .build();
    }
}

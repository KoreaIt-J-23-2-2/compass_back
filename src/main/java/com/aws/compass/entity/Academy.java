package com.aws.compass.entity;

import com.aws.compass.dto.MyAcademyNamesRespDto;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@NoArgsConstructor
@AllArgsConstructor
@Data
public class Academy {
    @JsonProperty("ACADEMY_ID")
    private int ACADEMY_ID;
    @JsonProperty("ATPT_OFCDC_SC_CODE")
    private String ATPT_OFCDC_SC_CODE;
    @JsonProperty("ATPT_OFCDC_SC_NM")
    private String ATPT_OFCDC_SC_NM;
    @JsonProperty("ADMST_ZONE_NM")
    private String ADMST_ZONE_NM;
    @JsonProperty("ACA_INSTI_SC_NM")
    private String ACA_INSTI_SC_NM;
    @JsonProperty("ACA_ASNUM")
    private String ACA_ASNUM;
    @JsonProperty("ACA_NM")
    private String ACA_NM;
    @JsonProperty("ESTBL_YMD")
    private String ESTBL_YMD;
    @JsonProperty("REG_YMD")
    private String REG_YMD;
    @JsonProperty("REG_STTUS_NM")
    private String REG_STTUS_NM;
    @JsonProperty("CAA_BEGIN_YMD")
    private String CAA_BEGIN_YMD;
    @JsonProperty("CAA_END_YMD")
    private String CAA_END_YMD;
    @JsonProperty("TOFOR_SMTOT")
    private String TOFOR_SMTOT;
    @JsonProperty("DTM_RCPTN_ABLTY_NMPR_SMTOT")
    private String DTM_RCPTN_ABLTY_NMPR_SMTOT;
    @JsonProperty("REALM_SC_NM")
    private String REALM_SC_NM;
    @JsonProperty("LE_ORD_NM")
    private String LE_ORD_NM;
    @JsonProperty("LE_CRSE_LIST_NM")
    private String LE_CRSE_LIST_NM;
    @JsonProperty("LE_CRSE_NM")
    private String LE_CRSE_NM;
    @JsonProperty("PSNBY_THCC_CNTNT")
    private String PSNBY_THCC_CNTNT;
    @JsonProperty("THCC_OTHBC_YN")
    private String THCC_OTHBC_YN;
    @JsonProperty("BRHS_ACA_YN")
    private String BRHS_ACA_YN;
    @JsonProperty("FA_RDNMA")
    private String FA_RDNMA;
    @JsonProperty("FA_RDNDA")
    private String FA_RDNDA;
    @JsonProperty("FA_RDNZC")
    private String FA_RDNZC;
    @JsonProperty("FA_TELNO")
    private String FA_TELNO;
    @JsonProperty("LOAD_DTM")
    private String LOAD_DTM;
    private String logoImg;

    public MyAcademyNamesRespDto toMyAcademyNamesRespDto() {
        return MyAcademyNamesRespDto.builder()
                .academyId(ACADEMY_ID)
                .acaNm(ACA_NM)
                .build();
    }
}

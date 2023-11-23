package com.aws.compass.dto;

import com.aws.compass.entity.AcademyInquiry;
import com.aws.compass.entity.Inquiry;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

import java.util.List;

@Builder
@Data
@AllArgsConstructor
public class AcademyInquiriesRespDto {
    private List<AcademyInquiry> inquiries;
    private int listTotalCount;
}

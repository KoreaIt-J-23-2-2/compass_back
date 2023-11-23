package com.aws.compass.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@NoArgsConstructor
@AllArgsConstructor
@Data
public class AcademyInquiryReqDto {
    private int userId;
    private int academyId;
    private int page;
    private int unansweredOnly;
}

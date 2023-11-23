package com.aws.compass.dto;

import com.aws.compass.entity.AcademyRegistration;
import com.aws.compass.entity.Inquiry;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

import java.util.List;

@Builder
@Data
@AllArgsConstructor
public class UserInquiriesRespDto {
    private List<Inquiry> inquiries;
    private int listTotalCount;
    private int uncheckedInquiryCount;
}

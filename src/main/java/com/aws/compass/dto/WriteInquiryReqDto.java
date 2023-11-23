package com.aws.compass.dto;

import com.aws.compass.entity.Inquiry;
import lombok.Data;

import javax.validation.constraints.Min;
import javax.validation.constraints.NotBlank;

@Data
public class WriteInquiryReqDto {
    @Min(0)
    private int userId;
    @Min(0)
    private int academyId;
    @NotBlank
    private String inquiryTitle;
    @NotBlank
    private String inquiryContent;
    private int answerChecked;

    public Inquiry toInquiry() {
        return Inquiry.builder()
                .userId(userId)
                .academyId(academyId)
                .inquiryTitle(inquiryTitle)
                .inquiryContent(inquiryContent)
                .answerChecked(answerChecked)
                .build();
    }
}

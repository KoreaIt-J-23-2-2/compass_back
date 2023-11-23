package com.aws.compass.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@NoArgsConstructor
@AllArgsConstructor
@Data
public class AcademyInquiry {
    private int inquiryId;
    private int academyId;
    private String acaNm;
    private String nickname;
    private String inquiryTitle;
    private String inquiryContent;
    private String answer;
    private int answerChecked;

}

package com.aws.compass.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@NoArgsConstructor
@AllArgsConstructor
@Data
public class Inquiry {
    private int inquiryId;
    private int userId;
    private int academyId;
    private String acaNm;
    private String inquiryTitle;
    private String inquiryContent;
    private String answer;
    private int answerChecked;

}

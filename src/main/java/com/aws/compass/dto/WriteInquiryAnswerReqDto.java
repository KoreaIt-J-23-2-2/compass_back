package com.aws.compass.dto;

import com.aws.compass.entity.Inquiry;
import lombok.Data;

import javax.validation.constraints.Min;
import javax.validation.constraints.NotBlank;

@Data
public class WriteInquiryAnswerReqDto {
    @NotBlank
    private String answer;
    private int answerChecked;

    public Inquiry toInquiry() {
        return Inquiry.builder()
                .answer(answer)
                .answerChecked(answerChecked)
                .build();
    }
}

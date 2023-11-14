package com.aws.compass.entity;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@NoArgsConstructor
@AllArgsConstructor
@Data
public class AcademyInfo {
    private int academy_info_id;
    @JsonProperty("ACADEMY_ID")
    private int ACADEMY_ID;
    private int user_id;
    private String logo_img;
    private String class_size;
    private String course_period;
    private String purpose;
    private String home_page;
    private String phone;
}

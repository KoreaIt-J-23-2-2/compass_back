package com.aws.compass.dto;

import com.aws.compass.entity.*;
import lombok.Data;

import java.util.List;

@Data
public class EditAcademyInfoReqDto {
    private AcademyInfo academyInfo;
    private List<Convenience> convenience;
    private List<Age> age;
    private List<ClassInfo> classInfo;
}

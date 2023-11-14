package com.aws.compass.dto;

import com.aws.compass.entity.Academy;
import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.List;

@AllArgsConstructor
@Data
public class AcademyListRespDto {
    private int listTotalCount;
    private List<Academy> academies;
}

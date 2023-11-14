package com.aws.compass.dto;

import lombok.Builder;
import lombok.Data;

@Builder
@Data
public class CategoryDetailRespDto { // 정보등록 응답 데이터 DTO
    private int CategoryDetailId;
    private String categoryValue;
    private String categoryDetailValue;
    private String categoryDetailName;
}

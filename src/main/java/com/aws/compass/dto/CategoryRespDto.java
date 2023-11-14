package com.aws.compass.dto;

import lombok.Builder;
import lombok.Data;

@Builder
@Data
public class CategoryRespDto { // 정보등록 응답 데이터 DTO
    private int categoryId;
    private String categoryValue;
    private String categoryName;
}

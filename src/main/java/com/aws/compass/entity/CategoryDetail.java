package com.aws.compass.entity;

import com.aws.compass.dto.CategoryDetailRespDto;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@NoArgsConstructor
@AllArgsConstructor
@Data
public class CategoryDetail {
    private int categoryDetailId;
    private String categoryValue;
    private String categoryDetailValue;
    private String categoryDetailName;

    public CategoryDetailRespDto toCategoryDetailDto() {
        return CategoryDetailRespDto.builder()
                .CategoryDetailId(categoryDetailId)
                .categoryValue(categoryValue)
                .categoryDetailValue(categoryDetailValue)
                .categoryDetailName(categoryDetailName)
                .build();
    }
}

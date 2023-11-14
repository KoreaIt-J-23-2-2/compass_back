package com.aws.compass.entity;

import com.aws.compass.dto.CategoryRespDto;
import com.aws.compass.dto.EducationOfficeRespDto;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@NoArgsConstructor
@AllArgsConstructor
@Data
public class Category {
    private int categoryId;
    private String categoryValue;
    private String categoryName;

    public CategoryRespDto toCategoryDto() {
        return CategoryRespDto.builder()
                .categoryId(categoryId)
                .categoryValue(categoryValue)
                .categoryName(categoryName)
                .build();
    }
}

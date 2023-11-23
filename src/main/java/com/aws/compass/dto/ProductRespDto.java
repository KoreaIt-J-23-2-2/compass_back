package com.aws.compass.dto;

import com.aws.compass.entity.Product;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ProductRespDto {

    private int productId;
    private String productName;
    private int productPrice;
    private int productPeriod;

}

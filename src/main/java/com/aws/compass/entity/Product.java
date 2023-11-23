package com.aws.compass.entity;

import com.aws.compass.dto.ProductRespDto;
import com.aws.compass.dto.PurchaseInfoRespDto;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Product {

    private int productId;
    private String productName;
    private int productPrice;
    private int productPeriod;
    private Date purchaseDate;

    public ProductRespDto toProduct() {
        return ProductRespDto.builder()
                .productId(productId)
                .productName(productName)
                .productPrice(productPrice)
                .productPeriod(productPeriod)
                .build();
    }

    public PurchaseInfoRespDto toPurchaseInfoDto() {
        return PurchaseInfoRespDto.builder()
                .productName(productName)
                .productPrice(productPrice)
                .productPeriod(productPeriod)
                .purchaseDate(purchaseDate)
                .build();
    }
}

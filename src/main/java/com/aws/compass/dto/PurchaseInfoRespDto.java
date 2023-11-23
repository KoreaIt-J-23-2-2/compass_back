package com.aws.compass.dto;

import lombok.Builder;
import lombok.Data;

import java.util.Date;

@Data
@Builder
public class PurchaseInfoRespDto {

    private String productName;
    private int productPrice;
    private int productPeriod;
    private Date purchaseDate;
}

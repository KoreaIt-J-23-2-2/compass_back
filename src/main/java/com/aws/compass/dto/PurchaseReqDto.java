package com.aws.compass.dto;

import com.aws.compass.entity.Purchase;
import lombok.Builder;
import lombok.Data;

import java.util.Date;

@Data
@Builder
public class PurchaseReqDto {

    private int purchaseInfoId;
    private int academyId;
    private int userId;
    private int productId;
    private Date purchaseDate;
    private int productPeriod;

    public Purchase toPurchase() {
        return Purchase.builder()
                .purchaseInfoId(purchaseInfoId)
                .academyId(academyId)
                .userId(userId)
                .productId(productId)
                .purchaseDate(purchaseDate)
                .build();
    }

}

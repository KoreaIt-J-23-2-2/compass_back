package com.aws.compass.entity;

import com.aws.compass.dto.PurchaseReqDto;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Purchase {

    private int purchaseInfoId;
    private int academyId;
    private int userId;
    private int productId;
    private Date purchaseDate;
    private int productPeriod;

    public PurchaseReqDto toPurchase() {
        return PurchaseReqDto.builder()
                .purchaseInfoId(purchaseInfoId)
                .academyId(academyId)
                .userId(userId)
                .productId(productId)
                .purchaseDate(purchaseDate)
                .build();
    }
}

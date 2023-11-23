package com.aws.compass.service;

import com.aws.compass.dto.ProductRespDto;
import com.aws.compass.dto.PurchaseInfoRespDto;
import com.aws.compass.dto.PurchaseReqDto;
import com.aws.compass.repository.PaymentMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

@Service
@RequiredArgsConstructor
public class PaymentService {

    private final PaymentMapper paymentMapper;

    public List<ProductRespDto> getProducts() {
        List<ProductRespDto> productRespDtos = new ArrayList<>();
        paymentMapper.getProducts().forEach(product -> {
            productRespDtos.add(product.toProduct());
        });
        return productRespDtos;
    }

    public boolean purchase(PurchaseReqDto purchaseReqDto) {
        return paymentMapper.savePurchase(purchaseReqDto.toPurchase()) > 0;
    }

    public PurchaseInfoRespDto isPurchase(int userId, int academyId) {
        if(!Objects.isNull(paymentMapper.checkPurchase(userId, academyId))) {
            return paymentMapper.checkPurchase(userId, academyId).toPurchaseInfoDto();
        }
        return null;
    }
}

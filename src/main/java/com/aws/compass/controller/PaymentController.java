package com.aws.compass.controller;

import com.aws.compass.dto.PurchaseReqDto;
import com.aws.compass.service.PaymentService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
public class PaymentController {

    private final PaymentService paymentService;

    @GetMapping("/api/ad/products")
    public ResponseEntity<?> getProducts() {
        return ResponseEntity.ok(paymentService.getProducts());
    }

    @PostMapping("/api/purchase")
    public ResponseEntity<?> purchase(@RequestBody PurchaseReqDto purchaseReqDto) {
        return ResponseEntity.ok(paymentService.purchase(purchaseReqDto));
    }

    @GetMapping("/api/purchase/check")
    public ResponseEntity<?> getPurchaseInfo(@RequestParam int userId, @RequestParam int academyId) {
        return ResponseEntity.ok(paymentService.isPurchase(userId, academyId));
    }
}

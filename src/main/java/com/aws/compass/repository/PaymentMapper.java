package com.aws.compass.repository;

import com.aws.compass.entity.Academy;
import com.aws.compass.entity.Product;
import com.aws.compass.entity.Purchase;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

@Mapper
public interface PaymentMapper {

    public List<Product> getProducts();
    public int savePurchase(Purchase purchase);
    public Product checkPurchase(int userId, int academyId);
}

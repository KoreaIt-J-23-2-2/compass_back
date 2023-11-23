package com.aws.compass.repository;

import com.aws.compass.entity.Academy;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

@Mapper
public interface AdvertisementMapper {

    public List<Academy> getADOfRandomAcademies();
}

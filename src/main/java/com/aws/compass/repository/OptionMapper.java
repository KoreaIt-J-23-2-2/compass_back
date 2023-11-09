package com.aws.compass.repository;


import com.aws.compass.entity.AdministrativeDistrict;
import com.aws.compass.entity.EducationOffice;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

@Mapper
public interface OptionMapper {
    public List<EducationOffice> getEducationOfficeList();
    public List<AdministrativeDistrict> getAdministrativeDistrictList();

}

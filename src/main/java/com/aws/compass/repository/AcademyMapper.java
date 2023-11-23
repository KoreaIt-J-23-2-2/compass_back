package com.aws.compass.repository;

import com.aws.compass.entity.*;
import com.aws.compass.vo.AcademySearchVo;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

@Mapper
public interface AcademyMapper {
    public int academyDuplicate(int academyId);
    public int academyRegist(AcademyRegistration academyRegistration);
    public int updateAcademyRegist(AcademyRegistration academyRegistration);
    public List<Academy> getAcademies(AcademySearchVo academySearchVo);
    public Academy getAcademy(int ACADEMY_ID);
    public AcademyInfo getAcademyInfo(int ACADEMY_ID);
    public List<Convenience> getConvenience(int ACADEMY_ID);
    public List<Age> getAgeRange(int ACADEMY_ID);
    public List<ClassInfo> getClassInfo(int ACADEMY_ID);
    public int getListTotalCount(AcademySearchVo academySearchVo);
    public List<AcademyRegistration> getAppliedAcademyRegistrations(int userId, int index);
    public int getAppliedAcademyCount(int userId);
    public List<AcademyRegistration> getMyAcademyRegistrations(int userId, int index);
    public int getMyAcademyCount(int userId);
    public List<Review> getAcademyReviews(int academyId);
    public int getRegisteredAcademy(int academyId);
    public int updateAcademyInfo(AcademyInfo academyInfo);
    public int insertAcademyInfo(AcademyInfo academyInfo);
    public int deleteAge(int academyInfoId);
    public int insertAge(int academyInfoId, int ageId);
    public int deleteConvenience(int academyInfoId);
    public int insertConvenience(int academyInfoId, int convenienceId);
    public int deleteClassInfo(int academyInfoId);
    public int insertClassInfo(int academyInfoId, ClassInfo classInfo);
    public ReviewCount getAcademyReviewCount(int academyId);
    public int writeReview(Review review);
    public int reviewDuplicate(Review review);
    public Review getMyReview(int academyId, int userId);
    public int updateReview(Review review);
    public int deleteReview(int academyId, int userId);
    public List<Academy> getAcademyByuserId(int userId);
}

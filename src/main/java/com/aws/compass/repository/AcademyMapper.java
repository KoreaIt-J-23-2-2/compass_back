package com.aws.compass.repository;

import com.aws.compass.dto.ReviewReqDto;
import com.aws.compass.dto.SearchAcademysReqDto;
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
    public int updateAcademyInfo(AcademyInfo academyInfo);
    public ReviewCount getAcademyReviewCount(int academyId);
    public int writeReview(Review review);
    public int reviewDuplicate(Review review);
    public Review getMyReview(int academyId, int userId);
    public int updateReview(Review review);
    public int deleteReview(int academyId, int userId);
}

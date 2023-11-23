package com.aws.compass.service;

import com.aws.compass.dto.*;
import com.aws.compass.entity.*;
import com.aws.compass.exception.AcademyException;
import com.aws.compass.exception.ReviewException;
import com.aws.compass.repository.AcademyMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
public class AcademyService {

    private final AcademyMapper academyMapper;

    @Transactional(rollbackFor = Exception.class)
    public boolean academyRegist(AcademyRegistrationReqDto academyRegistrationReqDto) {
        AcademyRegistration academyRegistration = academyRegistrationReqDto.toAcademyRegist();

        int errorCode = academyMapper.academyDuplicate(academyRegistration.getAcademyId());
        if(errorCode > 0) {
            throw new AcademyException("이미 등록된 학원입니다.");
        }
        return academyMapper.academyRegist(academyRegistration) > 0;
    }

    @Transactional(rollbackFor = Exception.class)
    public boolean updateAcademyRegist(int academyRegistrationId, AcademyRegistrationReqDto academyRegistrationReqDto) {
        AcademyRegistration academyRegistration = academyRegistrationReqDto.toAcademyRegist();
        academyRegistration.setAcademyRegistrationId(academyRegistrationId);

        return academyMapper.updateAcademyRegist(academyRegistration) > 0;
    }

    public AcademyListRespDto getAcademies(SearchAcademysReqDto searchAcademysReqDto) {
        int listTotalCount = academyMapper.getListTotalCount(searchAcademysReqDto.toVo());
        List<Academy> academies = academyMapper.getAcademies(searchAcademysReqDto.toVo());
        return new AcademyListRespDto(listTotalCount, academies);
    }

    public AcademyInfoRespDto getAcademy(int ACADEMY_ID) {
        Academy academy = academyMapper.getAcademy(ACADEMY_ID);
        AcademyInfo academyInfo  = academyMapper.getAcademyInfo(ACADEMY_ID);
        List<Convenience> convenienceInfo = academyMapper.getConvenience(ACADEMY_ID);
        List<Age> ageRange = academyMapper.getAgeRange(ACADEMY_ID);
        List<ClassInfo> classInfo = academyMapper.getClassInfo(ACADEMY_ID);
        return new AcademyInfoRespDto(academy, academyInfo, convenienceInfo, ageRange, classInfo);
    }

    public AppliedAcademiesRespDto getAppliedAcademies(int userId, int page) {
        int index = (page - 1) * 5;

        List<AcademyRegistration> academyRegistrations = academyMapper.getAppliedAcademyRegistrations(userId, index);
        int listTotalCount = academyMapper.getAppliedAcademyCount(userId);

        return new AppliedAcademiesRespDto(academyRegistrations, listTotalCount);
    }

    public MyAcademiesRespDto getMyAcademies(int userId, int page) {
        int index = (page - 1) * 5;

        List<AcademyRegistration> academyRegistrations = academyMapper.getMyAcademyRegistrations(userId, index);
        int listTotalCount = academyMapper.getMyAcademyCount(userId);

        return new MyAcademiesRespDto(academyRegistrations, listTotalCount);
    }

    public ReviewListRespDto getAcademyReviews(int academyId) {
        return new ReviewListRespDto(academyMapper.getAcademyReviews(academyId), academyMapper.getAcademyReviewCount(academyId));
    }
  
    public List<MyAcademyNamesRespDto> getMyAcademyNames(int userId) {
        List<MyAcademyNamesRespDto> myAcademyNamesRespDtos = new ArrayList<>();
        academyMapper.getAcademyByuserId(userId).forEach(academy -> myAcademyNamesRespDtos.add(academy.toMyAcademyNamesRespDto()));
        return myAcademyNamesRespDtos;
    }

    public ReviewRespDto getAcademyReviews(int academyId) {
        return new ReviewRespDto(academyMapper.getAcademyReviews(academyId), academyMapper.getAcademyReviewCount(academyId));
    }

    @Transactional(rollbackFor = Exception.class)
    public boolean editAcademyInfo(EditAcademyInfoReqDto editAcademyInfoReqDto) {
        AcademyInfo academyInfo = editAcademyInfoReqDto.getAcademyInfo();
        academyMapper.updateAcademyInfo(academyInfo);

        List<Age> ages = editAcademyInfoReqDto.getAge();
        academyMapper.deleteAge(academyInfo.getAcademyInfoId());
        ages.forEach(age -> {
            academyMapper.insertAge(academyInfo.getAcademyInfoId(), age.getAgeId());
        });

        List<Convenience> conveniences = editAcademyInfoReqDto.getConvenience();
        academyMapper.deleteConvenience(academyInfo.getAcademyInfoId());
        conveniences.forEach(convenience -> {
            academyMapper.insertConvenience(academyInfo.getAcademyInfoId(), convenience.getConvenienceId());
        });

        List<ClassInfo> classInfos = editAcademyInfoReqDto.getClassInfo();
        academyMapper.deleteClassInfo(academyInfo.getAcademyInfoId());
        classInfos.forEach(classInfo -> {
            academyMapper.insertClassInfo(academyInfo.getAcademyInfoId(), classInfo);
        });
        return true;
    }

    @Transactional(rollbackFor = Exception.class)
    public boolean addAcademyInfo(EditAcademyInfoReqDto editAcademyInfoReqDto) {
        AcademyInfo academyInfo = editAcademyInfoReqDto.getAcademyInfo();
        return academyMapper.insertAcademyInfo(academyInfo) > 0;
    }
  
    public boolean writeReview(ReviewReqDto reviewReqDto) {
        Review review = reviewReqDto.toReview();
        int errorCode = academyMapper.reviewDuplicate(review);
        if(errorCode > 0) {
            throw new ReviewException( "후기작성은 한 번만 가능합니다.\n작성한 후기의 수정, 삭제만 가능합니다.");
        }
        return academyMapper.writeReview(review) > 0;
    }

    public ReviewRespDto getMyReview(int academyId, int userId) {
        return new ReviewRespDto(academyMapper.getMyReview(academyId, userId));
    }

    public boolean modifyReview(ReviewReqDto reviewReqDto) {
        return academyMapper.updateReview(reviewReqDto.toReview()) > 0;
    }

    public boolean deleteReview(int academyId, int userId) {
        return academyMapper.deleteReview(academyId, userId) > 0;
    }
  
    public boolean isAcademyRegistered(int academyId) {
        return academyMapper.getRegisteredAcademy(academyId) > 0;
    }
}
















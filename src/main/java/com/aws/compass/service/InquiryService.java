package com.aws.compass.service;

import com.aws.compass.dto.*;
import com.aws.compass.entity.AcademyInquiry;
import com.aws.compass.entity.AcademyInquiryReqDto;
import com.aws.compass.entity.AcademyRegistration;
import com.aws.compass.entity.Inquiry;
import com.aws.compass.repository.InpuiryMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.RequestBody;

import java.util.List;

@Service
@RequiredArgsConstructor
public class InquiryService {
    private final InpuiryMapper inpuiryMapper;

    @Transactional(rollbackFor = Exception.class)
    public boolean writeInquiry(WriteInquiryReqDto inquiryReqDto) {
        Inquiry inquiry = inquiryReqDto.toInquiry();
        return inpuiryMapper.saveInpuiry(inquiry) > 0;
    }

    public UserInquiriesRespDto getUserInquiries(int userId, int page) {
        int index = (page - 1) * 5;

        List<Inquiry> inquiries = inpuiryMapper.getUserInquiries(userId, index);
        int listTotalCount = inpuiryMapper.getUserInquiriesCount(userId);
        int uncheckedInquiryCount = inpuiryMapper.getUncheckedInquiry(userId);

        return new UserInquiriesRespDto(inquiries, listTotalCount, uncheckedInquiryCount);
    }

    public AcademyInquiriesRespDto getInquiryList(AcademyInquiryReqDto inquiryReqDto) {
        int index = (inquiryReqDto.getPage() - 1) * 5;
        int userId = inquiryReqDto.getUserId();
        int academyId = inquiryReqDto.getAcademyId();
        int unansweredOnly = inquiryReqDto.getUnansweredOnly();
        List<AcademyInquiry> inquiries = inpuiryMapper.getAcademyInquiries(userId, index, academyId, unansweredOnly);
        int listTotalCount = inpuiryMapper.getAcademyInquiriesCount(userId, academyId, unansweredOnly);

        return new AcademyInquiriesRespDto(inquiries, listTotalCount);
    }

    @Transactional(rollbackFor = Exception.class)
    public boolean writeInquiryAnswer(int inquiryId, WriteInquiryAnswerReqDto inquiryAnswerReqDto) {
        Inquiry inquiry = inquiryAnswerReqDto.toInquiry();
        inquiry.setInquiryId(inquiryId);
        return inpuiryMapper.updateInquiry(inquiry) > 0;
    }

    public boolean updateAnswerChecked(int inquiryId, int answerChecked) {
        return  inpuiryMapper.updateAnswerChecked(inquiryId, answerChecked)> 0;
    }

    public int getuncheckedAnswerCount(int userId) {
        return inpuiryMapper.getUncheckedInquiry(userId);
    }
}

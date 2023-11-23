package com.aws.compass.repository;


import com.aws.compass.entity.*;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

@Mapper
public interface InpuiryMapper {
    public int saveInpuiry(Inquiry inquiry);
    public int getUserInquiriesCount(int userId);
    public List<Inquiry> getUserInquiries(int userId, int index);
    public List<AcademyInquiry> getAcademyInquiries(int userId, int index, int academyId, int unansweredOnly);
    public int getAcademyInquiriesCount(int userId, int academyId, int unansweredOnly);
    public int updateInquiry(Inquiry inquiry);
    public int updateAnswerChecked(int inquiryId, int answerChecked);
    public int getUncheckedInquiry(int userId);
}

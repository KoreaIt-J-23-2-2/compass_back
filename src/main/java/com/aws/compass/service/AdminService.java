package com.aws.compass.service;

import com.aws.compass.dto.ApprovalAcademyReqDto;
import com.aws.compass.dto.AwaitingAcademiesRepDto;
import com.aws.compass.repository.AdminMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
public class AdminService {

    private final AdminMapper adminMapper;

    public List<AwaitingAcademiesRepDto> getAwaitingAcademies(int page) {
        int index = (page - 1) * 5;

        List<AwaitingAcademiesRepDto> awaitingAcademiesRepDto = new ArrayList<>();
        adminMapper.getAwaitingAcademies(index).forEach(academy -> {
            awaitingAcademiesRepDto.add(academy.toAwaitingAcademiesDto());
        });
        return awaitingAcademiesRepDto;
    }

    public int getAwaitingAcademyCount() {
        return adminMapper.getAwaitingAcademyCount();
    }

    @Transactional(rollbackFor = Exception.class)
    public boolean approvalAcademy(ApprovalAcademyReqDto approvalAcademyReqDto) {
        return adminMapper.updateApprovalState(approvalAcademyReqDto.getAcademyRegistrationId()) > 0
                && adminMapper.updateUserRole(approvalAcademyReqDto.getUserId()) > 0;
    }

    @Transactional(rollbackFor = Exception.class)
    public boolean disapprovalAcademy(int academyRegistrationId) {
        return adminMapper.deleteByAcademyRegistrationId(academyRegistrationId) > 0;
    }
}

package com.aws.compass.controller;

import com.aws.compass.dto.ApprovalAcademyReqDto;
import com.aws.compass.service.AdminService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
public class AdminController {

    private final AdminService adminService;

    @GetMapping("/api/admin/academies/awaiting/{page}")
    public ResponseEntity<?> getAwaitingAcademies(@PathVariable int page) {
        return ResponseEntity.ok(adminService.getAwaitingAcademies(page));
    }

    @GetMapping("/api/admin/academies/awaiting/count")
    public ResponseEntity<?> getAwaitingAcademyCount() {
        return ResponseEntity.ok(adminService.getAwaitingAcademyCount());
    }

    @PutMapping("/api/admin/academy/approval")
    public ResponseEntity<?> approvalAcademy(@RequestBody ApprovalAcademyReqDto approvalAcademyReqDto) {
        return ResponseEntity.ok(adminService.approvalAcademy(approvalAcademyReqDto));
    }

    @DeleteMapping("/api/admin/academy/disapproval/{academyRegistrationId}")
    public ResponseEntity<?> disapprovalAcademy(@PathVariable int academyRegistrationId) {
        return ResponseEntity.ok(adminService.disapprovalAcademy(academyRegistrationId));
    }
}

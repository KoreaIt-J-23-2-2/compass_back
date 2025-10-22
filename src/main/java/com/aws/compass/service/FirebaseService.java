package com.aws.compass.service;

import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import org.springframework.stereotype.Service;

@Service
public class FirebaseService {
    public String createCustomToken(String firebaseUid) {
        try {
            return FirebaseAuth.getInstance().createCustomToken(firebaseUid);
        } catch (FirebaseAuthException e) {
            throw new RuntimeException("Firebase 토큰 생성 실패", e);
        }
    }
}
package com.aws.compass.config;

import com.google.auth.oauth2.GoogleCredentials;
import com.google.firebase.FirebaseApp;
import com.google.firebase.FirebaseOptions;
import org.springframework.context.annotation.Configuration;

import javax.annotation.PostConstruct;
import java.io.ByteArrayInputStream;

import java.io.InputStream;
import java.util.Base64;

@Configuration
public class FirebaseConfig {

    private String bucketName = "compass-firebase-c24d5.firebasestorage.app";

    @PostConstruct
    public void initialize() throws Exception {
        String firebaseBase64 = System.getenv("FIREBASE_CONFIG");

        if (firebaseBase64 == null || firebaseBase64.isEmpty()) {
            throw new IllegalStateException("FIREBASE_CONFIG 환경변수가 비어 있습니다.");
        }

        byte[] decodedBytes = Base64.getDecoder().decode(firebaseBase64);
        try (InputStream serviceAccount = new ByteArrayInputStream(decodedBytes)) {
            FirebaseOptions options = FirebaseOptions.builder()
                    .setStorageBucket(bucketName)
                    .setCredentials(GoogleCredentials.fromStream(serviceAccount))
                    .build();

            if (FirebaseApp.getApps().isEmpty()) {
                FirebaseApp.initializeApp(options);
            }
        }
    }
}

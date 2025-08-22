package com.aws.compass.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")      // 요청 엔드포인트
                .allowedOrigins("https://koreait-j-23-2-2.github.io","http://localhost:3000","https://3-34-44-250.sslip.io")   // 요청 서버 허용
                .allowedMethods("*")    // 요청 메소드 허용
                .allowedHeaders("*");
    }
}

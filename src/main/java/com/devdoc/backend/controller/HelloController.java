package com.devdoc.backend.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @GetMapping("/hello") // /hello 경로에 대한 GET 요청을 처리
    public String hello() {
        return "hello"; // "hello" 텍스트를 반환
    }
}

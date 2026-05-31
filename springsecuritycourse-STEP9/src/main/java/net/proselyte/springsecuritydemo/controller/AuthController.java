package net.proselyte.springsecuritydemo.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Slf4j
@Controller
@RequestMapping("/auth")
public class AuthController {

    @GetMapping("/login")
    public String getLoginPage() {
        log.info("GET /auth/login -> login page");
        return "login";
    }

    @GetMapping("/success")
    public String getSuccessPage() {
        log.info("GET /auth/success -> success page");
        return "success";
    }
}

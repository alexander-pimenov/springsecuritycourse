package net.proselyte.springsecurity.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

/*Стандартный контроллер для авторизации*/
@Controller
@RequestMapping("/auth/")
public class AuthController {

    //возвращает ссылку на страничку login.html
    @GetMapping("login")
    public String getLoginPage() {
        return "login";
    }
}

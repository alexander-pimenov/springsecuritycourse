package net.proselyte.springsecurity.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class SuccessController {

    //возвращает ссылку на страничку success.html
    @GetMapping("/success")
    public String getSuccessPage() {
        return "success";
    }
}

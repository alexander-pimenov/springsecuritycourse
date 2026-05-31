package net.proselyte.springsecuritydemo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * Контроллер для обработки аутентификации.
 * Управляет переходами на страницу входа и страницу успешной аутентификации.
 * Это не 'RestController', а 'Controller' для обработки запросов со страниц.
 */
@Controller
@RequestMapping("/auth")
public class AuthController {

    /**
     * Возвращает имя представления страницы входа.
     *
     * @return имя представления "login".
     * "login" - находится тут - src/main/resources/templates/login.html
     */
    @GetMapping("/login")
    public String getLoginPage() {
        return "login";
    }

    /**
     * Возвращает имя представления страницы успешной аутентификации.
     *
     * @return имя представления "success".
     * "success" - находится тут - src/main/resources/templates/success.html
     */
    @GetMapping("/success")
    public String getSuccessPage() {
        return "success";
    }
}

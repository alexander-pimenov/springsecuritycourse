package net.proselyte.springsecuritydemo.rest;

import lombok.Data;

/**
 * Класс для хранения логина+пароля для аутентификации пользователя.
 */
@Data
public class AuthenticationRequestDTO {
    private String email;
    private String password;
}

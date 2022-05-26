package net.proselyte.springsecuritydemo.rest;

import lombok.Data;

/*Класса, который нужен для хранения данных от пользователя.
* В нашем случае это email, пароль.*/
@Data
public class AuthenticationRequestDTO {
    private String email;
    private String password;
}

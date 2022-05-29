package net.proselyte.springsecuritydemo.repository;

import net.proselyte.springsecuritydemo.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

/*Интерфейс взаимодействующий с БД*/
public interface UserRepository extends JpaRepository<User, Long> {
    /*Главный идентификатор пользователя - это его email, поэтому его и будем искать*/
    Optional<User> findByEmail(String email);
}

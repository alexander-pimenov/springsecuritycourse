package net.proselyte.springsecuritydemo.repository;

import net.proselyte.springsecuritydemo.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

/**
 * Интерфейс взаимодействия с БД.
 */
public interface UserRepository extends JpaRepository<User, Long> {
    /**
     * Главный идентификатор пользователя, это его email.
     *
     * @param email - электронная почта пользователя.
     * @return - объект User.
     */
    Optional<User> findByEmail(String email);
}

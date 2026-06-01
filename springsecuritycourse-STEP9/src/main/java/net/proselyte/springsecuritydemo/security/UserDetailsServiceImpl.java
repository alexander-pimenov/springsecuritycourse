package net.proselyte.springsecuritydemo.security;

import lombok.extern.slf4j.Slf4j;
import net.proselyte.springsecuritydemo.model.User;
import net.proselyte.springsecuritydemo.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;


@Slf4j
@Service("userDetailsServiceImpl")
@Transactional(readOnly = true)
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    @Autowired
    public UserDetailsServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * Загружает данные пользователя из БД для аутентификации по email.
     *
     * <p>Ищет пользователя в {@link UserRepository} по email и оборачивает найденную
     * сущность {@link User} в {@link SecurityUser}, реализующий {@link UserDetails}.
     *
     * <p>
     * Обёртка нужна потому что Spring Security работает только с интерфейсом UserDetails,
     * а наша JPA-сущность User его не реализует. Конкретно обёртка решает три задачи:<br>
     * 1. Контракт с Spring Security — метод loadUserByUsername() обязан вернуть UserDetails.
     * Сущность User — это просто POJO с @Entity, Spring ничего не знает о её полях.<br>
     * 2. Маппинг прав доступа — UserDetails требует {@code Collection<? extends GrantedAuthority>}.
     * В сущности User роли и права хранятся в своём формате (Role.getAuthorities()),
     * обёртка преобразует их в SimpleGrantedAuthority, которые понимает Spring Security
     * (например, "developers:read").<br>
     * 3. Статус аккаунта — UserDetails требует 4 булевых метода: isAccountNonExpired,
     * isAccountNonLocked, isCredentialsNonExpired, isEnabled.
     * В нашем проекте все они маппятся на один флаг — Status.ACTIVE.<br>
     * <p>
     * Кстати, интересный момент: метод {@link SecurityUser#fromUser(User)} на самом деле возвращает встроенный
     * org.springframework.security.core.userdetails.User, а не сам SecurityUser.
     * Класс SecurityUser сейчас служит скорее документацией-адаптером — его можно использовать,
     * если понадобится кастомная логика (например, разные маппинги для разных статусов).
     *
     * @param email адрес электронной почты пользователя для загрузки
     * @return полностью заполненный объект {@link UserDetails} (никогда {@code null})
     * @throws UsernameNotFoundException если пользователь с указанным email не найден
     *
     */
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        log.info("Loading user by email: {}", email);
        User user = userRepository.findByEmail(email).orElseThrow(() -> {
            log.warn("User not found with email: {}", email);
            return new UsernameNotFoundException("User doesn't exists");
        });
        log.info("User found: {} with role: {}", email, user.getRole());
        return SecurityUser.fromUser(user);
    }
}

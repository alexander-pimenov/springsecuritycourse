package net.proselyte.springsecuritydemo.security;

import lombok.Data;
import net.proselyte.springsecuritydemo.model.Status;
import net.proselyte.springsecuritydemo.model.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

/**
 * Собственный класс User с названием SecurityUser, чтобы не путать со спринговым классом
 * User - {@link org.springframework.security.core.userdetails.User}. Он является
 * имплементацией интерфейса {@link UserDetails}
 */
@Data
public class SecurityUser implements UserDetails {

    private final String username;
    private final String password;
    private final List<SimpleGrantedAuthority> authorities;
    /**
     * В нашем случае свойство `isActive` отвечает за:<br>
     * - isAccountNonExpired <br>
     * - isAccountNonLocked <br>
     * - isCredentialsNonExpired <br>
     * - isEnabled <br>
     * <p>
     * Этого нам достаточно.
     */
    private final boolean isActive;

    public SecurityUser(String username, String password, List<SimpleGrantedAuthority> authorities, boolean isActive) {
        this.username = username;
        this.password = password;
        this.authorities = authorities;
        this.isActive = isActive;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return isActive;
    }

    @Override
    public boolean isAccountNonLocked() {
        return isActive;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return isActive;
    }

    @Override
    public boolean isEnabled() {
        return isActive;
    }

    /**
     * Преобразовывает {@link User}, хранящегося в БД, в реализацию интерфейса {@link UserDetails}.
     * Наш класс {@link SecurityUser} реализовывает этот интерфейс.
     * Класс {@link org.springframework.security.core.userdetails.User} также реализовывает
     * интерфейс {@link org.springframework.security.core.userdetails.UserDetails}.
     *
     * @param user - объект пользователя из БД, т.е. пользователя нашего приложения.
     * @return - объект {@link UserDetails}. Он может работать со Spring Security.
     */
    public static UserDetails fromUser(User user) {
        return new org.springframework.security.core.userdetails.User(
                user.getEmail(), user.getPassword(),
                user.getStatus().equals(Status.ACTIVE),
                user.getStatus().equals(Status.ACTIVE),
                user.getStatus().equals(Status.ACTIVE),
                user.getStatus().equals(Status.ACTIVE),
                user.getRole().getAuthorities()
        );
    }
}

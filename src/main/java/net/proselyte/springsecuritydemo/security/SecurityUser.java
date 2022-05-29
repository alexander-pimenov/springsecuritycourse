package net.proselyte.springsecuritydemo.security;

import lombok.Data;
import net.proselyte.springsecuritydemo.model.Status;
import net.proselyte.springsecuritydemo.model.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Data
public class SecurityUser implements UserDetails {

    //поля для User
    private final String username;
    private final String password;

    /*Коллекция разрешений SimpleGrantedAuthority*/
    private final List<SimpleGrantedAuthority> authorities;
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

    /*Здесь мы преобразовываем юзера User из нашей БД в UserDetails
    * */
    public static UserDetails fromUser(User user) {
        return new org.springframework.security.core.userdetails.User(
                user.getEmail(),
                user.getPassword(),
                //чтобы работал юзер, мы ему дадим статус ACTIVE, если будет что-то другое,
                //например BANNED, то нам не дадут вход в систему
                //для этого и проверяем на равенство со статусом ACTIVE
                user.getStatus().equals(Status.ACTIVE),
                user.getStatus().equals(Status.ACTIVE),
                user.getStatus().equals(Status.ACTIVE),
                user.getStatus().equals(Status.ACTIVE),
                //вытаскиваем его разрешения
                user.getRole().getAuthorities()
        );
    }
}

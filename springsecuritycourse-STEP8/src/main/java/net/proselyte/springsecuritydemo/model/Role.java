package net.proselyte.springsecuritydemo.model;

import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Set;
import java.util.stream.Collectors;

/**
 * Роли для разграничения доступа по ролям.
 * Каждая роль имеет еще свои полномочия (пермишены).
 */
public enum Role {
    /**
     * Пользователь с ролью USER имеет полномочия только - читать.
     */
    USER(Set.of(Permission.DEVELOPERS_READ)),
    /**
     * Пользователь с ролью ADMIN имеет полномочия и читать и писать.
     */
    ADMIN(Set.of(Permission.DEVELOPERS_READ, Permission.DEVELOPERS_WRITE));

    private final Set<Permission> permissions;

    /**
     * Роль. И каждой роли мы передаем набор полномочий.
     *
     * @param permissions - набор полномочий для роли.
     */
    Role(Set<Permission> permissions) {
        this.permissions = permissions;
    }

    /**
     * Геттер, чтобы получать пермишены.
     *
     * @return набор пермишенов.
     */
    public Set<Permission> getPermissions() {
        return permissions;
    }

    /**
     * Возвращает набор полномочий (authorities) для Spring Security.
     * Каждый {@link Permission} преобразуется в объект {@link SimpleGrantedAuthority},
     * который используется Spring Security для проверки прав доступа.
     * Т.е. для работы системы Spring Security, нужно конвертировать пермишены из ролей
     * в объект {@link SimpleGrantedAuthority}.
     *
     * @return набор {@link SimpleGrantedAuthority}, содержащий все полномочия данной роли.
     */
    public Set<SimpleGrantedAuthority> getAuthorities() {
        return getPermissions().stream()
                .map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
                .collect(Collectors.toSet());
    }
}

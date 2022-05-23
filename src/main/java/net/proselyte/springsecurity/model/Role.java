package net.proselyte.springsecurity.model;


import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Set;
import java.util.stream.Collectors;

/*Связываем нашили РОЛИ с РАЗРЕШЕНИЯМИ*/
public enum Role {
    USER(Set.of(Permission.DEVELOPERS_READ)),
    ADMIN(Set.of(Permission.DEVELOPERS_READ, Permission.DEVELOPERS_WRITE));

    Role(Set<Permission> permissions) {
        this.permissions = permissions;
    }

    private final Set<Permission> permissions;

    public Set<Permission> getPermissions() {
        return permissions;
    }

    /* SimpleGrantedAuthority - это сущность, которая позволяет определить Security кто и к чему имеет доступ
     * Конвертируем наши РОЛИ и РАЗРЕШЕНИЯ в эту сущность.*/
    public Set<SimpleGrantedAuthority> getAuthorities() {
        return getPermissions().stream()
                .map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
                .collect(Collectors.toSet());
    }
}

package net.proselyte.springsecuritydemo.model;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class RoleTest {

    @Test
    void userRole_shouldHaveReadPermission() {
        Set<Permission> permissions = Role.USER.getPermissions();

        assertTrue(permissions.contains(Permission.DEVELOPERS_READ));
        assertFalse(permissions.contains(Permission.DEVELOPERS_WRITE));
    }

    @Test
    void adminRole_shouldHaveReadAndWritePermissions() {
        Set<Permission> permissions = Role.ADMIN.getPermissions();

        assertTrue(permissions.contains(Permission.DEVELOPERS_READ));
        assertTrue(permissions.contains(Permission.DEVELOPERS_WRITE));
    }

    @Test
    void userRole_shouldHaveOneAuthority() {
        Set<SimpleGrantedAuthority> authorities = Role.USER.getAuthorities();

        assertEquals(1, authorities.size());
        assertTrue(authorities.contains(new SimpleGrantedAuthority("developers:read")));
    }

    @Test
    void adminRole_shouldHaveTwoAuthorities() {
        Set<SimpleGrantedAuthority> authorities = Role.ADMIN.getAuthorities();

        assertEquals(2, authorities.size());
        assertTrue(authorities.contains(new SimpleGrantedAuthority("developers:read")));
        assertTrue(authorities.contains(new SimpleGrantedAuthority("developers:write")));
    }
}

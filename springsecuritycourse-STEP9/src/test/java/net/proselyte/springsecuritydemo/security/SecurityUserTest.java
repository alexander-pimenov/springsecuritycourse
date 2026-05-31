package net.proselyte.springsecuritydemo.security;

import net.proselyte.springsecuritydemo.model.Role;
import net.proselyte.springsecuritydemo.model.Status;
import net.proselyte.springsecuritydemo.model.User;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.UserDetails;

import static org.junit.jupiter.api.Assertions.*;

class SecurityUserTest {

    @Test
    void fromUser_shouldMapActiveUser() {
        User user = new User();
        user.setEmail("user@test.com");
        user.setPassword("pass");
        user.setRole(Role.USER);
        user.setStatus(Status.ACTIVE);

        UserDetails userDetails = SecurityUser.fromUser(user);

        assertEquals("user@test.com", userDetails.getUsername());
        assertEquals("pass", userDetails.getPassword());
        assertTrue(userDetails.isEnabled());
        assertTrue(userDetails.isAccountNonExpired());
        assertTrue(userDetails.isAccountNonLocked());
        assertTrue(userDetails.isCredentialsNonExpired());
    }

    @Test
    void fromUser_shouldMapBannedUser() {
        User user = new User();
        user.setEmail("banned@test.com");
        user.setPassword("pass");
        user.setRole(Role.USER);
        user.setStatus(Status.BANNED);

        UserDetails userDetails = SecurityUser.fromUser(user);

        assertFalse(userDetails.isEnabled());
        assertFalse(userDetails.isAccountNonExpired());
        assertFalse(userDetails.isAccountNonLocked());
        assertFalse(userDetails.isCredentialsNonExpired());
    }

    @Test
    void fromUser_shouldMapAdminAuthorities() {
        User user = new User();
        user.setEmail("admin@test.com");
        user.setPassword("pass");
        user.setRole(Role.ADMIN);
        user.setStatus(Status.ACTIVE);

        UserDetails userDetails = SecurityUser.fromUser(user);

        assertEquals(2, userDetails.getAuthorities().size());
    }

    @Test
    void fromUser_shouldMapUserAuthorities() {
        User user = new User();
        user.setEmail("user@test.com");
        user.setPassword("pass");
        user.setRole(Role.USER);
        user.setStatus(Status.ACTIVE);

        UserDetails userDetails = SecurityUser.fromUser(user);

        assertEquals(1, userDetails.getAuthorities().size());
    }
}

package net.proselyte.springsecuritydemo.security;

import net.proselyte.springsecuritydemo.model.Role;
import net.proselyte.springsecuritydemo.model.Status;
import net.proselyte.springsecuritydemo.model.User;
import net.proselyte.springsecuritydemo.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserDetailsServiceImplTest {

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private UserDetailsServiceImpl userDetailsService;

    @Test
    void loadUserByUsername_shouldReturnUserDetailsForExistingUser() {
        User user = new User();
        user.setId(1L);
        user.setEmail("user@test.com");
        user.setPassword("encodedPassword");
        user.setRole(Role.USER);
        user.setStatus(Status.ACTIVE);

        when(userRepository.findByEmail("user@test.com")).thenReturn(Optional.of(user));

        UserDetails userDetails = userDetailsService.loadUserByUsername("user@test.com");

        assertNotNull(userDetails);
        assertEquals("user@test.com", userDetails.getUsername());
        assertEquals("encodedPassword", userDetails.getPassword());
        assertTrue(userDetails.isEnabled());
        assertTrue(userDetails.isAccountNonExpired());
        assertTrue(userDetails.isAccountNonLocked());
        assertTrue(userDetails.isCredentialsNonExpired());
    }

    @Test
    void loadUserByUsername_shouldReturnUserDetailsForBannedUser() {
        User user = new User();
        user.setId(2L);
        user.setEmail("banned@test.com");
        user.setPassword("encodedPassword");
        user.setRole(Role.USER);
        user.setStatus(Status.BANNED);

        when(userRepository.findByEmail("banned@test.com")).thenReturn(Optional.of(user));

        UserDetails userDetails = userDetailsService.loadUserByUsername("banned@test.com");

        assertFalse(userDetails.isEnabled());
        assertFalse(userDetails.isAccountNonExpired());
    }

    @Test
    void loadUserByUsername_shouldThrowExceptionForNonExistentUser() {
        when(userRepository.findByEmail("nonexistent@test.com")).thenReturn(Optional.empty());

        assertThrows(UsernameNotFoundException.class,
                () -> userDetailsService.loadUserByUsername("nonexistent@test.com"));
    }

    @Test
    void loadUserByUsername_shouldHaveCorrectAuthorities() {
        User user = new User();
        user.setEmail("admin@test.com");
        user.setPassword("pass");
        user.setRole(Role.ADMIN);
        user.setStatus(Status.ACTIVE);

        when(userRepository.findByEmail("admin@test.com")).thenReturn(Optional.of(user));

        UserDetails userDetails = userDetailsService.loadUserByUsername("admin@test.com");

        assertTrue(userDetails.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("developers:read")));
        assertTrue(userDetails.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("developers:write")));
    }

    @Test
    void loadUserByUsername_shouldHaveCorrectAuthoritiesForUserRole() {
        User user = new User();
        user.setEmail("user@test.com");
        user.setPassword("pass");
        user.setRole(Role.USER);
        user.setStatus(Status.ACTIVE);

        when(userRepository.findByEmail("user@test.com")).thenReturn(Optional.of(user));

        UserDetails userDetails = userDetailsService.loadUserByUsername("user@test.com");

        assertTrue(userDetails.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("developers:read")));
        assertFalse(userDetails.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("developers:write")));
    }
}

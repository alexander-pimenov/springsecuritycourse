package net.proselyte.springsecuritydemo.rest;

import com.fasterxml.jackson.databind.ObjectMapper;
import net.proselyte.springsecuritydemo.model.Role;
import net.proselyte.springsecuritydemo.model.Status;
import net.proselyte.springsecuritydemo.model.User;
import net.proselyte.springsecuritydemo.repository.UserRepository;
import net.proselyte.springsecuritydemo.security.JwtTokenProvider;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Optional;

import static org.hamcrest.Matchers.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = AuthenticationRestControllerV1.class,
            excludeAutoConfiguration = SecurityAutoConfiguration.class)
class AuthenticationRestControllerV1Test {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private AuthenticationManager authenticationManager;

    @MockBean
    private UserRepository userRepository;

    @MockBean
    private JwtTokenProvider jwtTokenProvider;

    @Test
    void authenticate_shouldReturnTokenForValidCredentials() throws Exception {
        AuthenticationRequestDTO request = new AuthenticationRequestDTO();
        request.setEmail("user@test.com");
        request.setPassword("password");

        User user = new User();
        user.setId(1L);
        user.setEmail("user@test.com");
        user.setPassword("encodedPassword");
        user.setRole(Role.USER);
        user.setStatus(Status.ACTIVE);

        when(userRepository.findByEmail("user@test.com")).thenReturn(Optional.of(user));
        when(jwtTokenProvider.createToken("user@test.com", "USER")).thenReturn("generated.jwt.token");

        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email", is("user@test.com")))
                .andExpect(jsonPath("$.token", is("generated.jwt.token")));
    }

    @Test
    void authenticate_shouldReturn403ForInvalidCredentials() throws Exception {
        AuthenticationRequestDTO request = new AuthenticationRequestDTO();
        request.setEmail("user@test.com");
        request.setPassword("wrong");

        doThrow(new BadCredentialsException("Bad credentials"))
                .when(authenticationManager).authenticate(any());

        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isForbidden())
                .andExpect(content().string("Invalid email/password combination"));
    }

    @Test
    void authenticate_shouldReturn403ForNonExistentUser() throws Exception {
        AuthenticationRequestDTO request = new AuthenticationRequestDTO();
        request.setEmail("nonexistent@test.com");
        request.setPassword("password");

        when(userRepository.findByEmail("nonexistent@test.com")).thenReturn(Optional.empty());

        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isForbidden())
                .andExpect(content().string("Invalid email/password combination"));
    }

    @Test
    void logout_shouldReturnOk() throws Exception {
        mockMvc.perform(post("/api/v1/auth/logout"))
                .andExpect(status().isOk());
    }
}

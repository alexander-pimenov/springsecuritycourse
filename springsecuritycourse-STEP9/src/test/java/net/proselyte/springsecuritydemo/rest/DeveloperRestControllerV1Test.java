package net.proselyte.springsecuritydemo.rest;

import com.fasterxml.jackson.databind.ObjectMapper;
import net.proselyte.springsecuritydemo.model.Developer;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = DeveloperRestControllerV1.class,
            excludeAutoConfiguration = SecurityAutoConfiguration.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class DeveloperRestControllerV1Test {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void getAll_shouldReturnDevelopersList() throws Exception {
        mockMvc.perform(get("/api/v1/developers"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(3)))
                .andExpect(jsonPath("$[0].firstName", is("Ivan")))
                .andExpect(jsonPath("$[1].lastName", is("Sergeev")))
                .andExpect(jsonPath("$[2].id", is(3)));
    }

    @Test
    void getById_shouldReturnDeveloper() throws Exception {
        mockMvc.perform(get("/api/v1/developers/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.firstName", is("Ivan")))
                .andExpect(jsonPath("$.lastName", is("Ivanov")));
    }

    @Test
    void getById_shouldReturnNullForNonExistentId() throws Exception {
        mockMvc.perform(get("/api/v1/developers/999"))
                .andExpect(status().isOk())
                .andExpect(content().string(""));
    }

    @Test
    void create_shouldAddDeveloper() throws Exception {
        Developer newDev = new Developer(4L, "New", "Developer");

        mockMvc.perform(post("/api/v1/developers")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(newDev)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id", is(4)))
                .andExpect(jsonPath("$.firstName", is("New")))
                .andExpect(jsonPath("$.lastName", is("Developer")));
    }

    @Test
    void deleteById_shouldReturnOk() throws Exception {
        mockMvc.perform(delete("/api/v1/developers/1"))
                .andExpect(status().isOk());
    }
}

package net.proselyte.springsecurity.rest;

import net.proselyte.springsecurity.model.Developer;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@RestController
@RequestMapping("/api/v1/developers")
public class DeveloperRestControllerV1 {
    private final List<Developer> DEVELOPERS = Stream.of(
            new Developer(1L, "Ivan", "Ivanov"),
            new Developer(2L, "Kolya", "Ivanov"),
            new Developer(3L, "Sergey", "Sergeev")
    ).collect(Collectors.toList());

    @GetMapping
    public List<Developer> getAll() {
        return DEVELOPERS;
    }

    /* Чтобы разграничить доступ к ресурсам (паттерны url) по РОЛЯМ не через antMatchers
     * (особенно если их много) в методе SecurityConfig#configure()
     * можно это делать прямо из Контроллера с помощью аннотаций @PreAuthorize*/
    //и это можно использовать @PreAuthorize("hasAuthority('developers:write')")
    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMIN')")
    public Developer getById(@PathVariable Long id) {
        return DEVELOPERS.stream()
                .filter(developer -> developer.getId().equals(id))
                .findFirst()
                .orElse(null);
    }

    //и это можно использовать  @PreAuthorize("hasAuthority('developers:write')")
    @PostMapping
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public Developer create(@RequestBody Developer developer) {
        this.DEVELOPERS.add(developer);
        return developer;
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('developers:write')")
    public void deleteById(@PathVariable Long id) {
        this.DEVELOPERS.removeIf(developer -> developer.getId().equals(id));
    }
}

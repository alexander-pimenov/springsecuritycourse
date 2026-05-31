package net.proselyte.springsecuritydemo.rest;

import net.proselyte.springsecuritydemo.model.Developer;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * REST-контроллер для работы с сущностью {@link Developer}.
 * Предоставляет REST API для получения, создания и удаления разработчиков.
 * <p>
 * Про аннотацию `@PreAuthorize`:<br>
 * - Аннотация Spring Security для ограничения доступа на уровне метода <br>
 * - Проверяет SpEL-выражение до выполнения метода <br>
 * - hasAuthority('developers:read') — проверяет, есть ли у пользователя это полномочие <br>
 * - Если проверка не прошла — выбрасывается AccessDeniedException, метод не выполняется <br>
 * <p>
 */
@RestController
@RequestMapping("/api/v1/developers")
public class DeveloperRestControllerV1 {
    /**
     * Локальное хранилище данных. Тестовый пример, без подключения БД.
     */
    private List<Developer> DEVELOPERS = Stream.of(
            new Developer(1L, "Ivan", "Ivanov"),
            new Developer(2L, "Sergey", "Sergeev"),
            new Developer(3L, "Petr", "Petrov")
    ).collect(Collectors.toList());

    /**
     * Возвращает список всех разработчиков.
     *
     * @return список {@link Developer}.
     */
    @GetMapping
    public List<Developer> getAll() {
        return DEVELOPERS;
    }

    /**
     * Возвращает разработчика по его идентификатору.
     * Доступен только пользователям с полномочием {@code developers:read}.
     *
     * @param id идентификатор разработчика.
     * @return объект {@link Developer} или {@code null}, если не найден.
     */
    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('developers:read')")
    public Developer getById(@PathVariable Long id) {
        return DEVELOPERS.stream().filter(developer -> developer.getId().equals(id))
                .findFirst()
                .orElse(null);
    }

    /**
     * Создает нового разработчика.
     * Доступен только пользователям с полномочием {@code developers:write}.
     *
     * @param developer данные нового разработчика, тело запроса, которое мапится в dto класс {@link Developer}
     * @return созданный объект {@link Developer}.
     */
    @PostMapping
    @PreAuthorize("hasAuthority('developers:write')")
    public Developer create(@RequestBody Developer developer) {
        this.DEVELOPERS.add(developer);
        return developer;
    }

    /**
     * Удаляет разработчика по его идентификатору.
     * Доступен только пользователям с полномочием {@code developers:write}.
     *
     * @param id идентификатор разработчика.
     */
    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('developers:write')")
    public void deleteById(@PathVariable Long id) {
        this.DEVELOPERS.removeIf(developer -> developer.getId().equals(id));
    }
}

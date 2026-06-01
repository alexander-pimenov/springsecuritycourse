package net.proselyte.springsecuritydemo.model;

import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;

/**
 * Вместо @Data используем:<br>
 * <p>
 * {@code @Getter}<br>
 * {@code @Setter}<br>
 * {@code @NoArgsConstructor}<br>
 * <p>
 * Чтобы не генерировать опасные:<br>
 * <p>
 * equals<br>
 * hashCode<br>
 * toString<br>
 * <p>
 * для JPA entity.
 */
//@Data
@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(name = "email")
    private String email;
    @Column(name = "password")
    private String password;
    @Column(name = "first_name")
    private String firstName;
    @Column(name = "last_name")
    private String lastName;
    @Enumerated(value = EnumType.STRING)
    @Column(name = "role")
    private Role role;
    @Enumerated(value = EnumType.STRING)
    @Column(name = "status")
    private Status status;
}

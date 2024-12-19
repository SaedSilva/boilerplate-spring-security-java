package br.dev.saed.boilerplatespringsecurityjava.dtos;


import br.dev.saed.boilerplatespringsecurityjava.entities.User;
import jakarta.validation.constraints.Email;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * DTO for {@link br.dev.saed}
 */
public class UserDTO implements Serializable {
    private Long id;
    @Email(message = "Favor entrar um email válido")
    private String email;
    private final List<RoleDTO> roles = new ArrayList<>();

    public UserDTO() {
    }

    public UserDTO(Long id, String email) {
        this.id = id;
        this.email = email;
    }

    public UserDTO(User entity) {
        id = entity.getId();
        email = entity.getEmail();
        entity.getRoles().forEach(role -> roles.add(new RoleDTO(role)));
    }

    public Long getId() {
        return id;
    }


    public String getEmail() {
        return email;
    }

    public List<RoleDTO> getRoles() {
        return roles;
    }
}
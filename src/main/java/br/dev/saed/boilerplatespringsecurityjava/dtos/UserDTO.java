package br.dev.saed.boilerplatespringsecurityjava.dtos;


import br.dev.saed.boilerplatespringsecurityjava.entities.User;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * DTO for {@link br.dev.saed}
 */
public class UserDTO implements Serializable {
    private final Long id;
    private final String email;
    private List<String> roles = new ArrayList<>();

    public UserDTO(Long id, String email) {
        this.id = id;
        this.email = email;
    }

    public UserDTO(User entity) {
        id = entity.getId();
        email = entity.getEmail();
        entity.getRoles().forEach(role -> roles.add(role.getAuthority()));
    }

    public Long getId() {
        return id;
    }


    public String getEmail() {
        return email;
    }

    public List<String> getRoles() {
        return roles;
    }
}
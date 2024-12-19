package br.dev.saed.boilerplatespringsecurityjava.dtos;

import br.dev.saed.boilerplatespringsecurityjava.entities.Role;

public class RoleDTO {

    private Long id;
    private String authority;

    public RoleDTO() {
    }

    public RoleDTO(Long id, String authority) {
        super();
        this.id = id;
        this.authority = authority;
    }

    public RoleDTO(Role role) {
        super();
        id = role.getId();
        authority = role.getAuthority();
    }

    public Long getId() {
        return id;
    }

    public String getAuthority() {
        return authority;
    }
}

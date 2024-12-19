package br.dev.saed.boilerplatespringsecurityjava.dtos;

import br.dev.saed.boilerplatespringsecurityjava.services.validation.UserInsertValid;

@UserInsertValid
public class UserInsertDTO extends UserDTO {
    private String password;

    public UserInsertDTO() {
        super();
    }

    public UserInsertDTO(Long id, String email, String password) {
        super(id, email);
        this.password = password;
    }

    public String getPassword() {
        return password;
    }
}

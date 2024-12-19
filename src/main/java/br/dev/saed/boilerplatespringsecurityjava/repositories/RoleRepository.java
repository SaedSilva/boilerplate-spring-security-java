package br.dev.saed.boilerplatespringsecurityjava.repositories;


import br.dev.saed.boilerplatespringsecurityjava.entities.Role;
import br.dev.saed.boilerplatespringsecurityjava.entities.User;
import br.dev.saed.boilerplatespringsecurityjava.projections.UserDetailsProjection;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;


public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByAuthority(String authority);
}

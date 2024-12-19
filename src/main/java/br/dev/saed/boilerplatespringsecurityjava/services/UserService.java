package br.dev.saed.boilerplatespringsecurityjava.services;

import br.dev.saed.boilerplatespringsecurityjava.dtos.UserDTO;
import br.dev.saed.boilerplatespringsecurityjava.dtos.UserInsertDTO;
import br.dev.saed.boilerplatespringsecurityjava.dtos.UserUpdateDTO;
import br.dev.saed.boilerplatespringsecurityjava.entities.Role;
import br.dev.saed.boilerplatespringsecurityjava.entities.User;
import br.dev.saed.boilerplatespringsecurityjava.projections.UserDetailsProjection;
import br.dev.saed.boilerplatespringsecurityjava.repositories.RoleRepository;
import br.dev.saed.boilerplatespringsecurityjava.repositories.UserRepository;
import br.dev.saed.boilerplatespringsecurityjava.services.exceptions.DatabaseException;
import br.dev.saed.boilerplatespringsecurityjava.services.exceptions.ResourceNotFoundException;
import jakarta.persistence.EntityNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
public class UserService implements UserDetailsService {

    @Autowired
    private UserRepository repository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Transactional(readOnly = true)
    public Page<UserDTO> findAll(Pageable pageable) {
        return repository.findAll(pageable).map(UserDTO::new);
    }

    @Transactional(readOnly = true)
    public UserDTO findById(Long id) {
        User entity = repository.findById(id).orElseThrow(() -> new ResourceNotFoundException("Resource not found"));
        return new UserDTO(entity);
    }

    @Transactional
    public UserDTO insert(UserInsertDTO dto) {
        User entity = new User();
        copyDtoToEntity(dto, entity);

        entity.getRoles().clear();
        Optional<Role> roleOptional = roleRepository.findByAuthority("ROLE_CLIENT");
        entity.addRole(roleOptional.orElseThrow(() -> new ResourceNotFoundException("Role não encontrada: ROLE_CLIENT")));

        entity.setPassword(passwordEncoder.encode(dto.getPassword()));
        entity = repository.save(entity);
        return new UserDTO(entity);
    }

    @Transactional
    public UserDTO update(Long id, UserUpdateDTO dto) {
        try {
            User entity = repository.getReferenceById(id);
            copyDtoToEntity(dto, entity);
            entity = repository.save(entity);
            return new UserDTO(entity);
        } catch (EntityNotFoundException e) {
            throw new ResourceNotFoundException("Id not found " + id);
        }
    }

    @Transactional(propagation = Propagation.SUPPORTS)
    public void delete(Long id) {
        if (!repository.existsById(id)) {
            throw new ResourceNotFoundException("Recurso não encontrado");
        }
        try {
            repository.deleteById(id);
        } catch (DataIntegrityViolationException e) {
            throw new DatabaseException("Falha de integridade referencial");
        }
    }


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        List<UserDetailsProjection> result = repository.searchUserAndRolesByEmail(username);
        if (result.isEmpty()) {
            throw new UsernameNotFoundException("User not found");
        }

        User user = new User();
        user.setEmail(username);
        user.setPassword(result.getFirst().getPassword());
        for (UserDetailsProjection u : result) {
            user.addRole(new Role(u.getRoleId(), u.getAuthority()));
        }
        return user;
    }

    protected User authenticated() {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication(); // Obtém o usuário autenticado
            Jwt jwtPrincipal = (Jwt) authentication.getPrincipal(); // Obtém o principal do token JWT
            String username = jwtPrincipal.getClaim("username"); // Obtém o email do usuário
            return repository.findByEmail(username).get(); // Busca o usuário no banco de dados e retorna
        } catch (Exception e) {
            throw new UsernameNotFoundException("User not found");
        }
    }

    @Transactional(readOnly = true)
    public UserDTO getMe() {
        return new UserDTO(authenticated());
    }

    private void copyDtoToEntity(UserDTO dto, User entity) {
        entity.setEmail(dto.getEmail());
        entity.getRoles().clear();
        dto.getRoles().forEach(x -> {
            Role role = roleRepository.getReferenceById(x.getId());
            entity.getRoles().add(role);
        });
    }
}

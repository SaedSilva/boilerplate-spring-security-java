package br.dev.saed.boilerplatespringsecurityjava.services;

import br.dev.saed.boilerplatespringsecurityjava.dtos.UserDTO;
import br.dev.saed.boilerplatespringsecurityjava.entities.Role;
import br.dev.saed.boilerplatespringsecurityjava.entities.User;
import br.dev.saed.boilerplatespringsecurityjava.projections.UserDetailsProjection;
import br.dev.saed.boilerplatespringsecurityjava.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class UserService implements UserDetailsService {

    @Autowired
    private UserRepository repository;

    @Override // Este método é chamado pelo Spring Security para buscar um usuário pelo email
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        List<UserDetailsProjection> result = repository.searchUserAndRolesByEmail(username);
        if (result.isEmpty()) {
            throw new UsernameNotFoundException("User not found");
        }

        User user = new User();
        user.setEmail(username);
        user.setPassword(result.get(0).getPassword());
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
}

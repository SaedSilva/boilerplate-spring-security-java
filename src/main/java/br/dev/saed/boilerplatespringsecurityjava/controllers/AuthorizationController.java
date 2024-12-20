package br.dev.saed.boilerplatespringsecurityjava.controllers;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.parameters.RequestBody;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/login")
public class AuthorizationController {
    @Operation(
            summary = "Obter token de acesso",
            description = "Gera um token de acesso usando OAuth2 Password Grant. Envie os dados no formato `application/x-www-form-urlencoded`.",
            security = @SecurityRequirement(name = "basicAuth"),
            responses = {
                    @ApiResponse(responseCode = "200", description = "Token gerado com sucesso"),
                    @ApiResponse(responseCode = "400", description = "Parâmetros inválidos"),
                    @ApiResponse(responseCode = "401", description = "Credenciais inválidas")
            }
    )
    @PostMapping(consumes = "application/x-www-form-urlencoded")
    public void login(
            @RequestParam @Parameter(description = "E-mail do usuário") String username,
            @RequestParam @Parameter(description = "Senha do usuário") String password,
            @RequestParam @Parameter(description = "Grant type, use 'password'") String grant_type
    ) {
        // Implementação gerenciada pelo Authorization Server
    }
}

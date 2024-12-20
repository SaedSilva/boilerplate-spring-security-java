package br.dev.saed.boilerplatespringsecurityjava;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.info.Info;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@OpenAPIDefinition(info = @Info(title = "Boiler plate Spring Security", version = "1", description = "Api desenvolvida para facilitar a vida de desenvolvedores para iniciar um projeto com spring security"))
public class BoilerplateSpringSecurityJavaApplication {

    public static void main(String[] args) {
        SpringApplication.run(BoilerplateSpringSecurityJavaApplication.class, args);
    }

}

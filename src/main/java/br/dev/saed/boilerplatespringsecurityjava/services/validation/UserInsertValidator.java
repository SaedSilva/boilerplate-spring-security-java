package br.dev.saed.boilerplatespringsecurityjava.services.validation;

import br.dev.saed.boilerplatespringsecurityjava.controllers.exceptions.FieldMessage;
import br.dev.saed.boilerplatespringsecurityjava.dtos.UserInsertDTO;
import br.dev.saed.boilerplatespringsecurityjava.entities.User;
import br.dev.saed.boilerplatespringsecurityjava.repositories.UserRepository;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class UserInsertValidator implements ConstraintValidator<UserInsertValid, UserInsertDTO> {
	
	@Autowired
	private UserRepository repository;
	
	@Override
	public void initialize(UserInsertValid ann) {
	}

	@Override
	public boolean isValid(UserInsertDTO dto, ConstraintValidatorContext context) {
		
		List<FieldMessage> list = new ArrayList<>();
		
		Optional<User> user = repository.findByEmail(dto.getEmail());
		if (user.isPresent()) {
			list.add(new FieldMessage("email", "Email já existe"));
		}

		for (FieldMessage e : list) {
			context.disableDefaultConstraintViolation();
			context.buildConstraintViolationWithTemplate(e.getMessage()).addPropertyNode(e.getFieldName())
					.addConstraintViolation();
		}
		return list.isEmpty();
	}
}

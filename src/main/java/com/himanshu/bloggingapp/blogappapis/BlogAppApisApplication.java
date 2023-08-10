package com.himanshu.bloggingapp.blogappapis;

import com.himanshu.bloggingapp.blogappapis.config.AppConstants;
import com.himanshu.bloggingapp.blogappapis.entities.Role;
import com.himanshu.bloggingapp.blogappapis.repositories.RoleRepository;
import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.info.Info;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;

@SpringBootApplication
@OpenAPIDefinition(info = @Info(title = "Blogging Application APIs", version = "2.0", description = "Blogging App Information"))
public class BlogAppApisApplication implements CommandLineRunner
{

	@Autowired
	private PasswordEncoder passwordEncoder;


	@Autowired
	private RoleRepository roleRepository;


	public static void main(String[] args) {
		SpringApplication.run(BlogAppApisApplication.class, args);
	}


	@Bean
	public ModelMapper modelMapper()
	{
		return new ModelMapper();
	}



	@Override
	public void run(String... args) throws Exception
	{
		System.out.println(this.passwordEncoder.encode("abcd"));


	try
	{
		Role role = new Role();
		role.setId(AppConstants.ADMIN_USER);
		role.setName("ADMIN_USER");


		Role role1 = new Role();
		role1.setId(AppConstants.NORMAL_USER);
		role1.setName("NORMAL_USER");


		List<Role> roles = List.of(role, role1);

		List<Role> result = this.roleRepository.saveAll(roles);


		result.forEach(r -> {
			System.out.println(r.getName());
		});

	}

		catch (Exception e)
		{
			e.printStackTrace();
		}

	}
}

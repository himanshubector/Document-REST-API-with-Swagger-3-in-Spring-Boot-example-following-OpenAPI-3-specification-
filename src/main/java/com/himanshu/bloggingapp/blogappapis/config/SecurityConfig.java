package com.himanshu.bloggingapp.blogappapis.config;


import com.himanshu.bloggingapp.blogappapis.security.CustomerUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;


@Configuration
@EnableWebSecurity
public class SecurityConfig
{

    @Autowired
    private CustomerUserDetailsService customerUserDetailsService;


    public static final String[] AUTH_WHITELIST = {
            "/authenticate",
            "/swagger-resources/**",
            "/swagger-ui/**",
            "/v3/api-docs",
            "/api/v1/auth/**",
            "/webjars/**"
    };


/*

    @Bean
    public UserDetailsService inMemoryUserDetailsManager()
    {
        UserDetails user = User.builder()
                                .username("user")
                                .password(passwordEncoder().encode("password"))
                                .roles("USER")
                                .build();


       */
/* UserDetails admin = User.builder()
                .username("admin")
                .password(passwordEncoder().encode("password"))
                .roles("USER", "ADMIN")
                .build();*//*



        return new InMemoryUserDetailsManager(user);
    }
*/



    @Bean
    public PasswordEncoder passwordEncoder()
    {
        return new BCryptPasswordEncoder();
    }



    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception
    {
            http.csrf(csrf -> csrf.disable())
                .cors(cors -> cors.disable())
                .authorizeHttpRequests(auth-> auth.requestMatchers(HttpMethod.GET)
                //.hasRole("USER")
                //.authenticated()
                .permitAll()
                .requestMatchers(AUTH_WHITELIST).permitAll());

                //.anyRequest()
               // .authenticated());


        return http.build();



      /*  Refer ->

                https://www.baeldung.com/spring-deprecated-websecurityconfigureradapter

                https://spring.io/blog/2022/02/21/spring-security-without-the-websecurityconfigureradapter


                https://www.codejava.net/frameworks/spring-boot/fix-websecurityconfigureradapter-deprecated


                https://www.appsdeveloperblog.com/migrating-from-deprecated-websecurityconfigureradapter/#Without_WebSecurityConfigurerAdapter


                https://backendstory.com/spring-security-how-to-replace-websecurityconfigureradapter/


                https://www.youtube.com/watch?v=7HQ-x9aoZx8


                https://howtodoinjava.com/spring-security/enablewebsecurity-annotation/




This Java code snippet is a configuration method for Spring Security using the Spring Security Java DSL (Domain-Specific Language). It sets up security filters and rules for handling HTTP requests based on the specified authorization and authentication settings. Let's go through the code line by line:

@Bean: This annotation indicates that the method is a Spring bean definition. It tells the Spring container that the return value of this method should be registered as a bean and managed by Spring.

public SecurityFilterChain filterChain(HttpSecurity http) throws Exception: This is the method signature. It defines a method named filterChain that takes an HttpSecurity parameter and returns a SecurityFilterChain object. The HttpSecurity class is a part of Spring Security and is used to configure security settings for an application.

http.authorizeRequests(): This starts the authorization configuration for the HTTP requests.

.requestMatchers("/login").permitAll(): This rule allows unauthenticated access (permit all) to the URL path "/login".

.requestMatchers("/**").authenticated(): This rule ensures that all other URL paths (/**) require authentication to access.

.and(): This is a chaining method used to combine multiple rules.

.formLogin().permitAll(): This enables a form-based login and allows unauthenticated access to the login page ("/login").

//@formatter:off: This is a code formatter comment that disables the code formatting for better readability of the configuration.

http.authorizeRequests(): This starts another authorization configuration block, which allows defining more specific rules.

.requestMatchers("/login").permitAll(): This is the same as line 4, allowing unauthenticated access to the login page.

.requestMatchers("/**").hasAnyRole("USER", "ADMIN"): This rule allows access to all other URL paths (/**) but requires the user to have either the "USER" or "ADMIN" role.

.requestMatchers("/admin/**").hasAnyRole("ADMIN"): This rule allows access to URL paths starting with "/admin/" and requires the user to have the "ADMIN" role.

.and(): This is used to combine multiple rules.

.formLogin(): This enables form-based login.

.loginPage("/login"): Sets the custom login page URL to "/login".

.loginProcessingUrl("/process-login"): Sets the URL where the login form should be submitted for processing.

.defaultSuccessUrl("/home"): Sets the default URL to redirect after successful login.

.failureUrl("/login?error=true"): Sets the URL to redirect after a failed login attempt.

.permitAll(): Allows unauthenticated access to the login and logout URLs.

.and(): Combines the form login configuration with the logout configuration.

.logout(): Enables logout support.

.logoutSuccessUrl("/login?logout=true"): Sets the URL to redirect after successful logout.

.invalidateHttpSession(true): Invalidates the HTTP session during logout.

.deleteCookies("JSESSIONID"): Deletes the "JSESSIONID" cookie during logout.

.permitAll(): Allows unauthenticated access to the logout URL.

.and(): Combines the logout configuration with the CSRF (Cross-Site Request Forgery) configuration.

.csrf().disable(): Disables CSRF protection for simplicity in this example. CSRF protection should generally be enabled in production environments.

//@formatter:on: This is a code formatter comment that enables code formatting after the configuration block.

return http.build(): This returns the configured HttpSecurity object.

In summary, this Java code configures Spring Security to allow unauthenticated access to the "/login" page and requires authentication for all other URLs. It also sets up role-based access control for certain URL patterns. Form-based login is enabled with custom login and logout pages, and CSRF protection is disabled for simplicity. Keep in mind that this is just a snippet of the entire Spring Security configuration, and other components, such as authentication providers, may be configured elsewhere in the application.

    */



    }



    /*
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer()
    {
        return (web) -> web.ignoring().requestMatchers("/resources/**", "/static/**");
    }*/




    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception
    {
        return authConfig.getAuthenticationManager();
    }




   /* @Bean
    public AuthenticationManager authManager(HttpSecurity http) throws Exception
    {
        return http.getSharedObject(AuthenticationManagerBuilder.class)
                .userDetailsService(inMemoryUserDetailsManager())
                .passwordEncoder(passwordEncoder())
                .and()
                .build();
    }*/




    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider()
    {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();

        authProvider.setUserDetailsService(this.customerUserDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());

        return authProvider;
    }




    /*@Bean
  AuthenticationSuccessHandler authenticationSuccessHandler()
  {
    return new CustomAuthenticationSuccessHandler();
  }



  @Bean
  AuthenticationFailureHandler authenticationFailureHandler()
  {
    return new CustomAuthenticationFailureHandler();
  }*/



    /*@Bean
    public SecurityFilterChain configure(HttpSecurity http) throws Exception
    {
        // Configure AuthenticationManagerBuilder
        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);

        authenticationManagerBuilder.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);


            http
                .cors(withDefaults())
                .csrf((csrf) -> csrf.disable())
                .authorizeHttpRequests((authz) -> authz
                        .requestMatchers(HttpMethod.POST, SecurityConstants.SIGN_UP_URL).permitAll()
                        .anyRequest().authenticated().and()

                        // User Authentication with custom login URL path
                        .addFilter(getAuthenticationFilter(authenticationManager))
                        // User Authorization with JWT
                        .addFilter(new AuthorizationFilter(authenticationManager, userRepository))
                        .authenticationManager(authenticationManager)
                        .sessionManagement((session) -> session
                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS));


        return http.build();


    }*/



}

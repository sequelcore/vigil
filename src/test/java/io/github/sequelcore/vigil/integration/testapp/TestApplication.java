package io.github.sequelcore.vigil.integration.testapp;

import io.github.sequelcore.vigil.autoconfigure.VigilProperties;
import io.github.sequelcore.vigil.filter.VigilAuthenticationFilter;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@SpringBootApplication
public class TestApplication {

  public static void main(String[] args) {
    SpringApplication.run(TestApplication.class, args);
  }

  @Bean
  SecurityFilterChain securityFilterChain(
      HttpSecurity http, VigilAuthenticationFilter authenticationFilter, VigilProperties properties)
      throws Exception {
    SecurityContextRepository securityContextRepository =
        new RequestAttributeSecurityContextRepository();
    authenticationFilter.setSecurityContextRepository(securityContextRepository);
    http.csrf(csrf -> csrf.csrfTokenRepository(new CookieCsrfTokenRepository()))
        .sessionManagement(
            session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .securityContext(context -> context.securityContextRepository(securityContextRepository))
        .authorizeHttpRequests(
            auth ->
                auth.requestMatchers(properties.filter().publicPaths().toArray(String[]::new))
                    .permitAll()
                    .requestMatchers("/protected/admin/**")
                    .hasRole("ADMIN")
                    .anyRequest()
                    .authenticated())
        .addFilterBefore(authenticationFilter, UsernamePasswordAuthenticationFilter.class);
    return http.build();
  }
}

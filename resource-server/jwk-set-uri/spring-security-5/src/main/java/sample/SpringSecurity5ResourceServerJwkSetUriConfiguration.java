package sample;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import static org.springframework.security.oauth2.jwt.NimbusJwtDecoder.withJwkSetUri;

@EnableWebSecurity
public class SpringSecurity5ResourceServerJwkSetUriConfiguration
		extends WebSecurityConfigurerAdapter {

	@Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}")
	String jwkSetUri;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off
		http
			.authorizeRequests()
				.antMatchers("/message/**").hasAuthority("SCOPE_message:read")
				.anyRequest().authenticated()
				.and()
			.oauth2ResourceServer()
				.jwt();
	}

	@Bean
	public JwtDecoder jwtDecoder() {
		return withJwkSetUri(this.jwkSetUri).build();
	}
}

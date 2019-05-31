package sample;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.jwk.JwkTokenStore;

@EnableResourceServer
@Configuration
public class SpringSecurityOAuthResourceServerJwkSetUriConfiguration
		extends ResourceServerConfigurerAdapter {

	@Value("${spring.security.oauth2.resource.jwk.key-set-uri}")
	String jwkSetUri;

	@Override
	public void configure(HttpSecurity http) throws Exception {
		// @formatter:off

		http
				.authorizeRequests()
						.antMatchers("/message/**").access("#oauth2.hasScope('message:read')")
						.anyRequest().authenticated();
	}

	@Bean
	public DefaultTokenServices jwkTokenServices(TokenStore jwkTokenStore) {
		DefaultTokenServices services = new DefaultTokenServices();
		services.setTokenStore(jwkTokenStore);
		return services;
	}

	@Bean
	public TokenStore jwkTokenStore() {
		return new JwkTokenStore(this.jwkSetUri);
	}
}

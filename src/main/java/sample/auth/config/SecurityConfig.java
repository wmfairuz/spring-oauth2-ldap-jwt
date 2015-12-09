package sample.auth.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Value("${myapp.ldap.url}")
    private String ldapUrl;
	
	@Value("${myapp.ldap.ldif}")
    private String ldapLdif;
	
	@Value("${myapp.ldap.user-dn-patterns}")
    private String ldapUserDnPatterns;
	
	@Value("${myapp.ldap.user-search-base}")
    private String ldapUserSearchBase;
	
	@Value("${myapp.ldap.group-search-base}")
    private String ldapGroupSearchBase;
	
	@Value("${myapp.ldap.group-search-filter}")
    private String ldapGroupSearchFilter;

	@Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth
			.ldapAuthentication()
			.userDnPatterns(ldapUserDnPatterns)
			.groupSearchBase(ldapGroupSearchBase)
			.contextSource()
//			.url(ldapUrl);
			.ldif(ldapLdif);
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean()
            throws Exception {
        return super.authenticationManagerBean();
    }
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }
	
}

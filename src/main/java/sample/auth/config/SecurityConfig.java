package sample.auth.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
//	@Value("${myapp.ldap.url}")
//    private String ldapUrl;
	
	@Value("${myapp.ldap.ldif}")
    private String ldapLdif;
	
	@Value("${myapp.ldap.user-dn-patterns}")
    private String ldapUserDnPatterns;
	
	@Value("${myapp.ldap.group}")
    private String ldapGroupSearchBase;

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
	
}

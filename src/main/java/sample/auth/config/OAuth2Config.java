package sample.auth.config;

import java.security.KeyPair;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.LdapUserDetailsService;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

@Configuration
@EnableAuthorizationServer
public class OAuth2Config extends AuthorizationServerConfigurerAdapter {

	@Value("${myapp.client.name:myapp}")
    private String clientName;
	
	@Value("${myapp.client.secret:myappsecret}")
    private String clientSecret;
	
	@Value("${myapp.client.scope:myapp}")
    private String clientScope;
	
	@Value("${myapp.keystore.name:keystore.jks}")
    private String keystore;
	
	@Value("${myapp.keystore.pass:keystorepass}")
    private String keystorepass;
	
	@Value("${myapp.key.name:myappkey}")
    private String key;
	
	@Value("${myapp.key.pass:keypass}")
    private String keypass;
	
	@Value("${myapp.ldap.url}")
    private String ldapUrl;
	
	@Value("${myapp.ldap.user-dn-patterns}")
    private String ldapUserDnPatterns;
	
	@Value("${myapp.ldap.user-search-base}")
    private String ldapUserSearchBase;
	
	@Value("${myapp.ldap.group-search-base}")
    private String ldapGroupSearchBase;
	
	@Value("${myapp.ldap.group-search-filter}")
    private String ldapGroupSearchFilter;
	
	@Autowired
	@Qualifier("authenticationManagerBean")
	private AuthenticationManager authenticationManager;

	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients.inMemory()
			.withClient(clientName)
			.secret(clientSecret)
			.accessTokenValiditySeconds(30)
			.refreshTokenValiditySeconds(600)
			.authorizedGrantTypes("refresh_token", "password")
			.scopes(clientScope);
	}
	
	/*
	 * JWT token
	 */
	@Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {       
        endpoints.authenticationManager(authenticationManager).accessTokenConverter(jwtAccessTokenConverter())
        	.userDetailsService(ldapUserDetailsManager());
    }
	
	@Bean
    public DefaultSpringSecurityContextSource contextSource() {
		return new DefaultSpringSecurityContextSource(ldapUrl);
    }
	
	@Bean 
	public FilterBasedLdapUserSearch userSearch() {
		return new FilterBasedLdapUserSearch(ldapUserSearchBase, "uid={0}", contextSource());
	}
	
	@Bean
	public DefaultLdapAuthoritiesPopulator ldapAuthoritiesPopulator() {
		DefaultLdapAuthoritiesPopulator authPopulator = new DefaultLdapAuthoritiesPopulator(contextSource(), ldapGroupSearchBase);
		authPopulator.setGroupSearchFilter(ldapGroupSearchFilter);
		return authPopulator;
	}
	
	@Bean
	public LdapUserDetailsService ldapUserDetailsManager() {
		return new LdapUserDetailsService(userSearch(), ldapAuthoritiesPopulator());
	}
    
    @Bean
	public JwtAccessTokenConverter jwtAccessTokenConverter() {
		JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
		KeyPair keyPair = new KeyStoreKeyFactory(
				new ClassPathResource(keystore), keystorepass.toCharArray())
				.getKeyPair(key, keypass.toCharArray());
		converter.setKeyPair(keyPair);
		return converter;
	}

	@Override
	public void configure(AuthorizationServerSecurityConfigurer oauthServer)
			throws Exception {
		oauthServer.tokenKeyAccess("permitAll()").checkTokenAccess("isAuthenticated()");
	}
	
}

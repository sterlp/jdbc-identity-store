## JEE/ CDI Integration

### IdentityStore configuration 
```java
@BasicAuthenticationMechanismDefinition(realmName = "bar")
@DeclareRoles({ "admin", "user" }) // this authorities are allowed
@ApplicationPath("")
public class ApplicationConfiguration extends Application {
 
    @Resource(lookup = "jdbc/identity-store") DataSource dataSource;
    @Produces
    @ApplicationScoped
    // @Priority(70)
    public org.sterl.identitystore.api.IdentityStore jdbcIdentityStore() {
        final org.sterl.identitystore.api.IdentityStore is = IdentityStoreBuilder.jdbcBuilder(dataSource)
                .withCache(Duration.ofMinutes(15))
                .withCachedPassword(true)
                .withPasswordQuery("select password from users where enabled = true AND username = ?")
                .withGroupsQuery("select authority from authorities where username = ?")
                .build();
        
        return is;
    }
}
```

### Example Java EE IdentityStore adapter
```java
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.security.enterprise.credential.BasicAuthenticationCredential;
import javax.security.enterprise.credential.UsernamePasswordCredential;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.security.enterprise.identitystore.IdentityStore;
import org.sterl.identitystore.api.VerificationResult;

@ApplicationScoped
public class JavaEEIdentityStore implements IdentityStore {

    @Inject org.sterl.identitystore.api.IdentityStore is;
    
    public CredentialValidationResult validate(BasicAuthenticationCredential credential) {
        VerificationResult vr = is.verify(credential.getCaller(), credential.getPasswordAsString());
        return new CredentialValidationResult(credential.getCaller(), vr.getGroups());
    }

    public CredentialValidationResult validate(UsernamePasswordCredential credential) {
        VerificationResult vr = is.verify(credential.getCaller(), credential.getPasswordAsString());
        return new CredentialValidationResult(credential.getCaller(), vr.getGroups());
    }
}
```


### Spring Boot integration

```java
@Configuration
@EnableGlobalMethodSecurity(
        prePostEnabled = true, 
        securedEnabled = true, 
        jsr250Enabled = true)
public class JdbcSecurityConfig extends WebSecurityConfigurerAdapter {
 
    @Autowired
    private DataSource dataSource;
     
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth)
      throws Exception {
        final IdentityStore identityStore = IdentityStoreBuilder.jdbcBuilder(dataSource)
            .withPasswordQuery("select password from users where enabled = true AND username = ?")
            .withGroupsQuery("select authority from authorities where username = ?")
            .withGroupPrefix("ROLE_")
            .withCache(Duration.ofMinutes(15))
            .withCachedPassword(true)
            .build();

        auth.authenticationProvider(new AuthenticationProvider() {
            @Override
            public boolean supports(Class<?> authentication) {
                return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
            }
            
            @Override
            public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                final UsernamePasswordAuthenticationToken auth = (UsernamePasswordAuthenticationToken)authentication;
                final VerificationResult verificationResult = identityStore.verify(auth.getName(), 
                        auth.getCredentials() == null ? null : auth.getCredentials().toString());
                
                if (verificationResult.getStatus() == Status.VALID) {
                    final List<SimpleGrantedAuthority> authorities = verificationResult.getGroups().stream().map(g -> new SimpleGrantedAuthority(g)).collect(Collectors.toList());
                    return new UsernamePasswordAuthenticationToken(
                            authentication.getPrincipal(), 
                            authentication.getCredentials(), 
                            authorities);
                } else {
                    throw new BadCredentialsException("Wrong user name or password.");
                }
            }
        });
``
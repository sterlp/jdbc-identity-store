## JDBC Identity store with the following goals

- compatible to spring boot
- compatible to Java EE / CDI
- provide a read through/ fallback cache for users, if the DB is gone
- provide a cache for users, to limit request count to thr DB
- provide a password cache to reduce the overhead of BCrypt for password checks - keeping BCrypt Hash in the DB

## Maven include

```xml
<dependency>
    <groupId>org.sterl.identitystore.jdbc</groupId>
    <artifactId>jdbc-identity-store</artifactId>
    <version>0.1.0</version>
</dependency>
```

### IdentityStore configuration 
```java
@BasicAuthenticationMechanismDefinition(realmName = "bar")
@DeclareRoles({ "admin", "user" }) // this authorities are allowed
@ApplicationPath("")
public class ApplicationConfiguration extends Application {
 
    @Resource(lookup = "jdbc/identity-store") DataSource dataSource;

    @Produces
    @ApplicationScoped
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
```

## Load Test

- 100 concurrent Threads
- 10.000 requests
- simple hello world resource
- local postgreSQL DB with three users

### Spring Boot with build in JDBC with BCrypt

```
GET.http://localhost:8080
             count = 10000
         mean rate = 1336,95 calls/second
     1-minute rate = 305,00 calls/second
     5-minute rate = 305,00 calls/second
    15-minute rate = 305,00 calls/second
               min = 1,54 milliseconds
               max = 4793,98 milliseconds
              mean = 67,24 milliseconds
            stddev = 406,63 milliseconds
            median = 26,20 milliseconds
              75% <= 33,47 milliseconds
              95% <= 68,99 milliseconds
              98% <= 127,74 milliseconds
              99% <= 396,62 milliseconds
            99.9% <= 4680,78 milliseconds
```

### Spring boot with jdbc-identity-store - no password cache
- With enabled cache

```
GET.http://localhost:8080
             count = 10000
         mean rate = 1740,52 calls/second
     1-minute rate = 1497,20 calls/second
     5-minute rate = 1497,20 calls/second
    15-minute rate = 1497,20 calls/second
               min = 1,75 milliseconds
               max = 2503,71 milliseconds
              mean = 51,06 milliseconds
            stddev = 202,91 milliseconds
            median = 31,03 milliseconds
              75% <= 39,60 milliseconds
              95% <= 75,31 milliseconds
              98% <= 111,44 milliseconds
              99% <= 149,81 milliseconds
            99.9% <= 2379,19 milliseconds 
```

### Spring boot with jdbc-identity-store - with password cache
- With enabled cache
- With enabled password cache
```
GET.http://localhost:8080
             count = 10000
         mean rate = 3401,78 calls/second
     1-minute rate = 0,00 calls/second
     5-minute rate = 0,00 calls/second
    15-minute rate = 0,00 calls/second
               min = 1,45 milliseconds
               max = 297,67 milliseconds
              mean = 28,26 milliseconds
            stddev = 29,05 milliseconds
            median = 22,83 milliseconds
              75% <= 29,87 milliseconds
              95% <= 57,20 milliseconds
              98% <= 116,14 milliseconds
              99% <= 156,62 milliseconds
            99.9% <= 286,60 milliseconds
```

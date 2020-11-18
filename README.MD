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
    <version>0.1.1</version>
</dependency>
```

## DB Schema

```sql
CREATE TABLE users (
  username VARCHAR(50) NOT NULL,
  password VARCHAR(250) NOT NULL,
  PRIMARY KEY (username)
);
  
CREATE TABLE groups (
  username VARCHAR(50) NOT NULL REFERENCES users(username) on delete cascade on update cascade,
  usergroup VARCHAR(50) NOT NULL,
  PRIMARY key (username, usergroup)
);
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
        return validate(credential.getCaller(),  credential.getPasswordAsString());
    }

    public CredentialValidationResult validate(UsernamePasswordCredential credential) {
        return validate(credential.getCaller(),  credential.getPasswordAsString());
    }
    
    private CredentialValidationResult validate(String user, String password) {
        final VerificationResult vr = is.verify(user, password);
        if (vr.getStatus() == VerificationResult.Status.VALID) {
            return new CredentialValidationResult(user, vr.getGroups());
        } else {
            return CredentialValidationResult.INVALID_RESULT;
        }
        
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

# Load Test
## Setup
- 100 concurrent Threads
- 10.000 requests
- simple hello world resource
- local postgreSQL DB with three users

*Note:* The performance overhead in this load test comes from BCrypt

## Spring Boot integration

### Spring Boot with build in JDBC with BCrypt

- SPring Boot does already some caching here ...

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

## Payara 4.1.2.181 / 5.2

- HTTP Thread Pool adjusted to 100 threads

### Payara @DatabaseIdentityStoreDefinition (soteria)

Using the build in JDBC store with @DatabaseIdentityStoreDefinition
No caches, basically shows the performance of BCrypt.

```
GET.http://localhost:8080
             count = 10000
         mean rate = 55,18 calls/second
     1-minute rate = 55,55 calls/second
     5-minute rate = 49,15 calls/second
    15-minute rate = 46,04 calls/second
               min = 1690,44 milliseconds
               max = 2244,49 milliseconds
              mean = 1765,04 milliseconds
            stddev = 54,04 milliseconds
            median = 1755,14 milliseconds
              75% <= 1787,40 milliseconds
              95% <= 1843,73 milliseconds
              98% <= 1913,47 milliseconds
              99% <= 1969,66 milliseconds
            99.9% <= 2225,13 milliseconds
```

### Payara with the IdentityStore with cache - with password cache

- With enabled cache
- With enabled password cache

```
GET.http://localhost:8080
             count = 10000
         mean rate = 2406,80 calls/second
     1-minute rate = 0,00 calls/second
     5-minute rate = 0,00 calls/second
    15-minute rate = 0,00 calls/second
               min = 19,02 milliseconds
               max = 291,96 milliseconds
              mean = 41,81 milliseconds
            stddev = 27,25 milliseconds
            median = 37,95 milliseconds
              75% <= 42,98 milliseconds
              95% <= 56,20 milliseconds
              98% <= 60,47 milliseconds
              99% <= 265,43 milliseconds
            99.9% <= 286,92 milliseconds
```

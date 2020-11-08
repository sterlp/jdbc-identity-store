package org.sterl.identitystore.builder;

import java.time.Duration;

import javax.sql.DataSource;

import org.sterl.hash.Algorithm;
import org.sterl.hash.BCryptPbkdf2PasswordHash;
import org.sterl.hash.PasswordHasher;
import org.sterl.identitystore.api.IdentityStore;
import org.sterl.identitystore.cache.IdentityStoreCache;
import org.sterl.identitystore.jdbc.JdbcIdentityStore;

import lombok.RequiredArgsConstructor;

/**
 * This class supports building an identity store.
 * @author sterlp
 */
@RequiredArgsConstructor(staticName = "jdbcBuilder")
public class IdentityStoreBuilder {

    private final DataSource dataSource;
    private PasswordHasher passwordHasher;
    private Duration cacheDuration;
    private boolean cachePassword = false;
    private String groupsQuery = JdbcIdentityStore.DEFAULT_GROUPS_QUERY;
    private String passwordQuery = JdbcIdentityStore.DEFAULT_PASSWORD_QUERY;
    private String groupPrefix;
    
    /**
     * Set the {@link PasswordHasher} with the desired configuration.
     * 
     * @param hasher the {@link PasswordHasher} to use, <code>null</code> to reset
     * @return this for chaining
     */
    public IdentityStoreBuilder withPasswordHasher(PasswordHasher hasher) {
        this.passwordHasher = hasher;
        return this;
    }
    /**
     * Creates the {@link PasswordHasher} with the given {@link Algorithm}
     * 
     * @param algorithm desired {@link Algorithm}
     * @return this for chaining
     */
    public IdentityStoreBuilder withHashAlgorithm(Algorithm algorithm) {
        passwordHasher = new BCryptPbkdf2PasswordHash(algorithm);
        return this;
    }
    
    /**
     * Enables the cache for identities, default is <code>no cache</code>. 
     * Set <code>null</code> to turn off the cache.
     * 
     * @param duration the time after which the identity should be reloaded, including the roles.
     * @return this for chaining
     */
    public IdentityStoreBuilder withCache(Duration duration) {
        this.cacheDuration = duration;
        return this;
    }
    
    /**
     * Activate or disable the caching of the clear text password, improves the password
     * check using BCrypt. <b>Not save as the password will stay in memory!</b>
     * 
     * @param value <code>true</code> cache password, default <code>false</code>
     * @return this for chaining
     */
    public IdentityStoreBuilder withCachedPassword(boolean value) {
        this.cachePassword = value;
        return this;
    }
    
    /**
     * Query to load the users groups form the JDBC store e.g.:
     * <pre>select usergroup from groups where username = ?</pre>
     * 
     * @param groupsQuery the SQL to load the user groups
     * @return this for chaining
     */
    public IdentityStoreBuilder withGroupsQuery(String groupsQuery) {
        this.groupsQuery = groupsQuery;
        return this;
    }
    /**
     * Query to load the user password form the JDBC store e.g.:
     * <pre>select password from users where username = ?</pre>
     * @param the query to load the hashed user password
     * @return this for chaining
     */
    public IdentityStoreBuilder withPasswordQuery(String passwordQuery) {
        this.passwordQuery = passwordQuery;
        return this;
    }
    
    /**
     * Spring requires that all roles are prefixed with <b>ROLE_</b>, this allows
     * to prefix the roles for spring.
     * 
     * @param groupPrefix optional prefix to add to any loaded role
     * @return this for chaining
     */
    public IdentityStoreBuilder withGroupPrefix(String groupPrefix) {
        this.groupPrefix = groupPrefix;
        return this;
    }
    
    /**
     * Builds the {@link IdentityStore}
     * 
     * @return {@link IdentityStore} with the selected config
     */
    public IdentityStore build() {
        IdentityStore result = new JdbcIdentityStore(dataSource, 
                passwordHasher == null ? new BCryptPbkdf2PasswordHash() : passwordHasher,
                passwordQuery, groupsQuery, groupPrefix);
        
        // wrap the JDBC store if the cache is enabled
        if (cacheDuration != null) {
            result = new IdentityStoreCache(result, cacheDuration, cachePassword);
        }

        return result;
    }
}

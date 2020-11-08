package org.sterl.identitystore.jdbc;

import java.sql.SQLException;

import javax.sql.DataSource;

import org.sterl.hash.PasswordHasher;
import org.sterl.identitystore.api.Identity;
import org.sterl.identitystore.api.IdentityStore;
import org.sterl.identitystore.api.VerificationResult;

import lombok.Getter;
import lombok.NonNull;

/**
 * Main goal of this identity store is to load and validate identities using a JDBC data source.
 * 
 * It allows the configuration of the password and the use groups query, default is:
 * <pre>
 * select password from users where username = ?
 * select usergroup from groups where username = ?
 * </pre>
 *
 * @author sterlp
 */
@Getter
public class JdbcIdentityStore implements IdentityStore {
    public static final String DEFAULT_PASSWORD_QUERY = "select password from users where username = ?";
    public static final String DEFAULT_GROUPS_QUERY = "select usergroup from groups where username = ?";

    /** PasswordHasher used to verify the passwords */
    @Getter @NonNull
    private final PasswordHasher passwordHasher;
    @NonNull
    private final JdbcIdentityStoreDao storeDao;
    
    /**
     * Spring requires that all roles are prefixed with <b>ROLE_</b>, this allows
     * to prefix the roles/ groups for spring.
     */
    private final String groupPrefix;
    
    /**
     * Creates a new identity store using the default queries.
     * 
     * @param dataSource {@link DataSource} to access the DB
     * @param passwordHasher {@link PasswordHasher} to verify the password
     */
    public JdbcIdentityStore(DataSource dataSource, PasswordHasher passwordHasher) {
        this(dataSource, passwordHasher, DEFAULT_PASSWORD_QUERY, DEFAULT_GROUPS_QUERY, null);
    }
    
    /**
     * Creates a new identity store using custom queries.
     * 
     * @param dataSource {@link DataSource} to access the DB
     * @param passwordHasher {@link PasswordHasher} to verify the password
     * @param passwordQuery Query to load the user password form the JDBC store using the username.
     * @param groupsQuery Query to load the user groups form the JDBC store using the username.
     * @param groupPrefix optional prefix which should be added to every group.
     */
    public JdbcIdentityStore(DataSource dataSource, PasswordHasher passwordHasher, 
            String passwordQuery, String groupsQuery, String groupPrefix) {
        this.passwordHasher = passwordHasher;
        this.storeDao = new JdbcIdentityStoreDao(dataSource, passwordQuery, groupsQuery);
        this.groupPrefix = groupPrefix;
    }
    
    /**
     * {@inheritDoc}
     */
    @Override
    public VerificationResult verify(String username, String inputPassword) {
        VerificationResult result;
        final Identity identity = load(username);
        result = identity.verify(inputPassword, passwordHasher);
        return result;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Identity load(String username) {
        try {
            final Identity result = storeDao.load(username);
            if (groupPrefix != null && groupPrefix.length() > 0) {
                result.prefixRole(groupPrefix);
            }
            return result;
        } catch (SQLException e) {
            throw new RuntimeException("Failed to load user informations for " + username, e);
        }
    }
}

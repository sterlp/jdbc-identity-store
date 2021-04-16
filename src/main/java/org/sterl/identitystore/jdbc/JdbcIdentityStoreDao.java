package org.sterl.identitystore.jdbc;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashSet;
import java.util.Set;

import javax.sql.DataSource;

import org.sterl.identitystore.api.Identity;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;

/**
 * Loads identities with its roles from the DB.
 * 
 * @author sterlp
 */
@AllArgsConstructor(access = AccessLevel.PACKAGE)
class JdbcIdentityStoreDao {
    
    private final DataSource dataSource;
    /**
     * Query to load the user password form the JDBC store e.g.:
     * <pre>select password from users where username = ?</pre>
     */
    private final String passwordQuery;
    /**
     * Query to load the users groups form the JDBC store e.g.:
     * <pre>select usergroup from groups where username = ?</pre>
     */
    private final String groupsQuery;

    /**
     * Loads the {@link Identity} data using it's user name.
     * 
     * @param username the name of the user
     * @return the found {@link Identity} or {@link Identity#NOT_FOUND}, never <code>null</code>
     * @throws SQLException if the configures queries are bad or DB connection interrupted
     * @throws IllegalStateException if the password isn't unique
     */
    Identity load(String username) throws SQLException {
        Identity result;
        try (Connection connection = dataSource.getConnection()) {
            final Set<String> userPassword = executeQuery(connection, passwordQuery, username);
            if (userPassword.isEmpty()) {
                result = Identity.NOT_FOUND;
            } else if (userPassword.size() > 1) {
                throw new IllegalStateException("Found " + userPassword.size() + " passwords for user " + username);
            } else {
                final Set<String> userGroups = executeQuery(connection, groupsQuery, username);
                result = new Identity(username, userPassword.iterator().next(), userGroups);
            }
        }
        return result;
    }
    
    private Set<String> executeQuery(Connection connection, String query, String parameter) throws SQLException {
        Set<String> result = new HashSet<>();

        try (PreparedStatement statement = connection.prepareStatement(query)) {
            statement.setString(1, parameter);
            try (ResultSet resultSet = statement.executeQuery()) {
                while (resultSet.next()) {
                    result.add(resultSet.getString(1));
                }
            }
        }

        return result;
    }
}

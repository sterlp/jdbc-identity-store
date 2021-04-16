package org.sterl.identitystore;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import javax.sql.DataSource;

import org.h2.jdbcx.JdbcDataSource;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.sterl.hash.Algorithm;
import org.sterl.identitystore.api.Identity;
import org.sterl.identitystore.api.IdentityStore;
import org.sterl.identitystore.api.VerificationResult;
import org.sterl.identitystore.builder.IdentityStoreBuilder;

public class IdentityStoresTest {

    static DataSource datasource;
    static String schema;

    @BeforeAll
    static void setup() throws Exception {
        JdbcDataSource ds = new JdbcDataSource();
        ds.setUrl("jdbc:h2:mem:test;DB_CLOSE_DELAY=-1;MODE=PostgreSQL");
        ds.setUser("sa");
        datasource = ds;
        schema = new String(Files.readAllBytes(Paths.get(
                IdentityStoresTest.class.getResource("/drop-create-default-shema.sql").getFile())));
        datasource = ds;
    }

    @BeforeEach
    void init() throws Exception {
        try (Connection c = datasource.getConnection()) {
            c.setAutoCommit(false);
            try (Statement s = c.createStatement()) {
                s.execute(schema);
            }
            c.commit();
        }
    }

    @Test
    void testJdbcIdentityStore() throws Exception {
        final IdentityStore subject = IdentityStoreBuilder
                .jdbcBuilder(datasource)
                .withHashAlgorithm(Algorithm.PBKDF2WithHmacSHA224)
                .build();

        for (int i = 1; i <= 10; i++) {
            createUser(new Identity("user_" + i, 
                    subject.getPasswordHasher().encode("pass_" + i), 
                    from("USER_" + i, "ADMIN")), datasource);
        }

        assertEquals(VerificationResult.NOT_FOUND, subject.verify("user", "foo"));
        assertEquals(VerificationResult.INVALID_PASSWORD, subject.verify("user_1", "foo"));
        assertEquals(VerificationResult.Status.VALID, subject.verify("user_2", "pass_2").getStatus());
        assertEquals(from("USER_1", "ADMIN"), subject.verify("user_1", "pass_1").getGroups());
    }
    
    @Test
    void testGroupPrefix() throws Exception {
        final IdentityStore subject = IdentityStoreBuilder
                .jdbcBuilder(datasource)
                .withHashAlgorithm(Algorithm.PBKDF2WithHmacSHA224)
                .withGroupPrefix("ROLE_")
                .build();
        
        createUser(new Identity("admin", 
                subject.getPasswordHasher().encode("pass"), 
                from("USER", "ADMIN")), datasource);
        createUser(new Identity("user", 
                subject.getPasswordHasher().encode("user"), 
                new HashSet<String>()), datasource);
        
         
        assertEquals(from("ROLE_USER", "ROLE_ADMIN"), subject.verify("admin", "pass").getGroups());
        assertEquals(Collections.EMPTY_SET, subject.verify("user", "user").getGroups());
    }
    
    private void createUser(Identity identity, DataSource dataSource) throws SQLException {
        try (Connection c = dataSource.getConnection()) {
            try (PreparedStatement s = c.prepareStatement("INSERT INTO users (username, password) VALUES(?, ?)")) {
                s.setString(1, identity.getUsername());
                s.setString(2, identity.getHashedPassword());
                s.execute();
            }
            
            if (!identity.getGroups().isEmpty()) {
                try (PreparedStatement s = c.prepareStatement("INSERT INTO groups (username, usergroup) VALUES(?, ?)")) {
                    for (String g : identity.getGroups()) {
                        s.setString(1, identity.getUsername());
                        s.setString(2, g);
                        s.addBatch();
                    }
                    s.executeBatch();
                }
            }
        }
    }
    
    private static Set<String> from(String... groups) {
        return new HashSet<>(Arrays.asList(groups));
    }
}

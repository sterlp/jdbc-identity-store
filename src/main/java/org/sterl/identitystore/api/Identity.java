package org.sterl.identitystore.api;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import org.sterl.hash.PasswordHasher;
import org.sterl.identitystore.api.VerificationResult.Status;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.ToString;

/**
 * Representation of a stored identity with it roles.
 * 
 * @author sterlp
 */
@AllArgsConstructor @Getter @ToString
public class Identity {
    @SuppressWarnings("unchecked")
    public static final Identity NOT_FOUND = new Identity(null, null, Collections.EMPTY_SET);

    private final String username;
    private final String hashedPassword;
    private final Set<String> groups;
    
    /**
     * Verifies the given password using the given hasher.
     * 
     * @param password the password to check
     * @param hasher the {@link PasswordHasher} to use
     * @return the {@link VerificationResult} of the check, never <code>null</code>
     */
    public VerificationResult verify(String password, PasswordHasher hasher) {
        VerificationResult result;
        if (this == NOT_FOUND) {
            result = VerificationResult.NOT_FOUND;
        } else if (hasher.matches(password, hashedPassword)) {
            result = new VerificationResult(Status.VALID, 
                    groups == null ? new HashSet<>() : new HashSet<>(groups));
        } else {
            result = VerificationResult.INVALID_PASSWORD;
        }
        return result;
    }
    
    /**
     * Creates from an array of strings a {@link Set}
     * 
     * @param groups the string groups
     * @return the {@link Set} with the given groups
     */
    public static Set<String> from(String... groups) {
        return new HashSet<>(Arrays.asList(groups));
    }

    /**
     * Adds the given prefix to all stored groups
     * @param groupPrefix the prefix to add
     */
    public void prefixRole(final String groupPrefix) {
        final Set<String> newGroups = this.groups.stream().map(g -> groupPrefix + g).collect(Collectors.toSet());
        this.groups.clear();
        this.groups.addAll(newGroups);
    }
}

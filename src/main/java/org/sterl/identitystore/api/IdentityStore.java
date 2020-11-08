package org.sterl.identitystore.api;

import org.sterl.hash.PasswordHasher;

/**
 * An identity store provides identities (a.k.a. users) for a Java application
 * which can be used to authenticate and authorize user access.
 * 
 * @author sterlp
 */
public interface IdentityStore {

    /**
     * Verifies the login of a user using user name and password.
     * 
     * @param username the entered user name
     * @param inputPassword the entered password
     * @return the {@link VerificationResult}, never <code>null</code>
     */
    VerificationResult verify(String username, String inputPassword);
    
    /**
     * Method primely used to chain {@link IdentityStore} using the composite pattern.
     * This method should use {@link Identity#NOT_FOUND} instead of <code>null</code>.
     * 
     * @param username the username to search for
     * @return the found {@link Identity} in the {@link IdentityStore}, should never the <code>null</code>
     */
    Identity load(String username);
    
    /**
     * @return the used {@link PasswordHasher} to verify the passwords against the store.
     */
    PasswordHasher getPasswordHasher();
}

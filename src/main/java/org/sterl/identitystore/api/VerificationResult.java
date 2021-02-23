
package org.sterl.identitystore.api;

import java.util.Collections;
import java.util.Set;

import lombok.Data;

/**
 * This class represents the result after a user/ password check against an identity store.
 * @author sterlp
 */
@Data
public class VerificationResult {
    /** Default result if the user is unknown */
    @SuppressWarnings("unchecked")
    public static final VerificationResult NOT_FOUND = new VerificationResult(Status.NOT_FOUND, Collections.EMPTY_SET);
    /** Default result if the user password was wrong */
    @SuppressWarnings("unchecked")
    public static final VerificationResult INVALID_PASSWORD = new VerificationResult(Status.INVALID_PASSWORD, Collections.EMPTY_SET);

    public enum Status {
        NOT_FOUND,
        INVALID_PASSWORD,
        VALID
    }

    private final Status status;
    private final Set<String> groups;
}

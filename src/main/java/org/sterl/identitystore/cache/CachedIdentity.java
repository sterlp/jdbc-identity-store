package org.sterl.identitystore.cache;

import java.time.Duration;

import org.sterl.hash.PasswordHasher;
import org.sterl.identitystore.api.Identity;
import org.sterl.identitystore.api.VerificationResult;
import org.sterl.identitystore.api.VerificationResult.Status;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@RequiredArgsConstructor 
@ToString(of = {"identity", "cachedTime"})
class CachedIdentity {
    @Getter @NonNull
    private final Identity identity;
    @Getter
    private final long cachedTime;
    @Setter @Getter(value = AccessLevel.PACKAGE)
    private String rawPassword;
    
    /** Indicates if this result is returned from the cache*/
    @Setter @Getter
    private boolean cacheHit = false;
    /** If an error was handled it is saved here */
    @Setter @Getter
    private Exception suppressedError = null;

    /**
     * Verifies the given password using the given hasher, if the {@link #rawPassword} is
     * set it will be used in the first place to check the password.
     * 
     * @param password the password to check
     * @param hasher the {@link PasswordHasher} to use
     * @return the {@link VerificationResult} of the check, never <code>null</code>
     */
    VerificationResult verify(String password, PasswordHasher hasher) {
        VerificationResult result;
        if (rawPassword != null && rawPassword.equals(password)) {
            result = new VerificationResult(Status.VALID, identity.getGroups());
        } else {
            result = identity.verify(password, hasher);
        }
        return result;
    }
    /**
     * @param duration the {@link Duration} to check
     * @return <code>true</code> if duration is exceeded, otherwise <code>false</code>
     */
    boolean isTimeout(Duration duration) {
        return duration.toMillis() < (System.currentTimeMillis() - cachedTime);
    }
}

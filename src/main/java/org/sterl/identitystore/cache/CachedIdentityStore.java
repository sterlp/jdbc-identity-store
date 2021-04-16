package org.sterl.identitystore.cache;

import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;

import org.sterl.hash.PasswordHasher;
import org.sterl.identitystore.api.Identity;
import org.sterl.identitystore.api.IdentityStore;
import org.sterl.identitystore.api.VerificationResult;
import org.sterl.identitystore.api.VerificationResult.Status;

import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/**
 * Provides the ability to cache any other identity store for two main purposes:
 * <ol>
 *  <li>As a fallback in case of a down time of the identity store which is cached.</li>
 *  <li>Improved performance to reduce the amount of calls to the wrapped {@link IdentityStore}.
 * </ol>
 * 
 * @author sterlp
 */
@RequiredArgsConstructor
public class CachedIdentityStore implements IdentityStore {
    @NonNull
    private final IdentityStore wrapped;

    /**
     * The time after which the identity should be reloaded, including the roles.
     * Will fallback to the cache entry is case of a reload problem.
     */
    @NonNull @Getter
    private final Duration cacheDuration;
    /** Allows to cache the real password to increase the performance using cached entries */
    @Getter
    private final boolean cacheRealPassword;
    private final ConcurrentHashMap<String, CachedIdentity> cache = new ConcurrentHashMap<>();

    @Override
    public VerificationResult verify(String username, String inputPassword) {
        CachedIdentity identity = loadWithFallbackToCache(username);
        VerificationResult result = identity.verify(inputPassword, wrapped.getPasswordHasher());

        // double check the result in case it fails
        if (result.getStatus() != Status.VALID) {
            identity = loadAndCache(username);
            result = identity.verify(inputPassword, wrapped.getPasswordHasher());
        }
        // if password cache is enabled, cache the password too
        if (cacheRealPassword && result.getStatus() == Status.VALID) {
            identity.setRawPassword(inputPassword);
        }
        result.setCacheHit(identity.isCacheHit());
        result.setSuppressedError(identity.getSuppressedError());
        return result;
    }

    @Override
    public PasswordHasher getPasswordHasher() {
        return wrapped.getPasswordHasher();
    }

    @Override
    public Identity load(String username) {
        return loadWithFallbackToCache(username).getIdentity();
    }
    
    CachedIdentity loadWithFallbackToCache(String username) {
        final CachedIdentity cachedIdentity = cache.get(username);
        CachedIdentity result;
        if (cachedIdentity == null || cachedIdentity.isTimeout(cacheDuration)) {
            try {
                result = loadAndCache(username);

                if (cachedIdentity != null && cachedIdentity.getRawPassword() != null
                        && cachedIdentity.getIdentity().getHashedPassword().equals(result.getIdentity().getHashedPassword())) {
                    result.setRawPassword(cachedIdentity.getRawPassword());
                }

            } catch (Exception e) {
                if (cachedIdentity == null) throw e;
                else {
                    result = cachedIdentity;
                    result.setCacheHit(true);
                    result.setSuppressedError(e);
                }
            }
        } else {
            result = cachedIdentity;
            result.setCacheHit(true);
        }
        return result;
    }

    /**
     * loads the identity from the underlining store and caches it if found. 
     */
    private CachedIdentity loadAndCache(String username) {
        final CachedIdentity result = new CachedIdentity(wrapped.load(username), 
                System.currentTimeMillis());
        // do not cache not found users
        if (result.getIdentity() != Identity.NOT_FOUND) {
            cache.put(username, result);
        }
        return result;
    }
}

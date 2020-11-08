package org.sterl.identitystore.cache;

import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.sterl.hash.PasswordHasher;
import org.sterl.identitystore.api.Identity;
import org.sterl.identitystore.api.IdentityStore;
import org.sterl.identitystore.api.VerificationResult;
import org.sterl.identitystore.api.VerificationResult.Status;

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
public class IdentityStoreCache implements IdentityStore {
    private static Logger LOG = Logger.getLogger(IdentityStoreCache.class.getSimpleName());
    @NonNull
    private final IdentityStore wrapped;
    @NonNull
    private final Duration cacheDuration;
    /** Allows to cache the real password to increase the performance using cached entries */
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
    
    private CachedIdentity loadWithFallbackToCache(String username) {
        CachedIdentity identity = cache.get(username);
        if (identity == null || identity.isTimeout(cacheDuration)) {
            try {
                identity = loadAndCache(username);
            } catch (Exception e) {
                if (identity == null) throw e;
                else {
                    LOG.log(Level.WARNING, "Failed to load " + username 
                            + " from " + wrapped.getClass().getSimpleName() 
                            + ", fallback to cached value.", e);
                }
            }
        }
        return identity;
    }

    /**
     * loads the identity from the underlining store and caches it if found. 
     */
    private CachedIdentity loadAndCache(String username) {
        final CachedIdentity result = new CachedIdentity(wrapped.load(username), 
                System.currentTimeMillis(), null);
        // do not cache not found users
        if (result.getIdentity() != Identity.NOT_FOUND) {
            cache.put(username, result);
        }
        return result;
    }
}

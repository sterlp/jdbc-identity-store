package org.sterl.identitystore.cache;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;

import org.junit.jupiter.api.Test;
import org.sterl.identitystore.api.Identity;
import org.sterl.identitystore.api.VerificationResult;
import org.sterl.identitystore.api.VerificationResult.Status;

public class CachedIdentityTest {

    @Test
    void testCache() {
        CachedIdentity identity = new CachedIdentity(
                new Identity("a", null, null), 0);
        identity.setRawPassword("passs");
        
        final VerificationResult check = identity.verify("passs", null);
        assertEquals(Status.VALID, check.getStatus());
    }
    
    @Test
    void tesTimeout() {
        // cached 100ms ago
        CachedIdentity identity = new CachedIdentity(
                new Identity("a", null, null), 
                System.currentTimeMillis() - 100);
        
        // only cache it for 99ms
        for (int i = 0; i < 100; i++) {
            assertTrue(identity.isTimeout(Duration.ofMillis(99)));
        }
        // 150ms should always run into the cache
        for (int i = 0; i < 100; i++) {
            assertFalse(identity.isTimeout(Duration.ofMillis(150)));
        }
    }
}

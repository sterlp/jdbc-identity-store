package org.sterl.identitystore.cache;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.sterl.identitystore.api.Identity;
import org.sterl.identitystore.api.VerificationResult;
import org.sterl.identitystore.api.VerificationResult.Status;

public class TestCachedIdentity {

    @Test
    void testCache() {
        CachedIdentity identity = new CachedIdentity(
                new Identity("a", null, null), 
                0, null);
        identity.setRawPassword("passs");
        
        final VerificationResult check = identity.verify("passs", null);
        assertEquals(Status.VALID, check.getStatus());
    }
}

package org.sterl.identitystore.cache;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.sterl.hash.BCryptPbkdf2PasswordHash;
import org.sterl.identitystore.api.Identity;
import org.sterl.identitystore.api.IdentityStore;
import org.sterl.identitystore.api.VerificationResult.Status;

public class TestIdentityStoreCache {

    private static final String USER_NAME = "user";
    private static final String USER_PASS = "pass";

    final BCryptPbkdf2PasswordHash hasher = new BCryptPbkdf2PasswordHash();
    final String password = hasher.encode(USER_PASS);
    IdentityStore wrapped;
    IdentityStoreCache subject;
    Identity identity;
    
    @BeforeEach
    void before() {
        wrapped = mock(IdentityStore.class);

        subject = new IdentityStoreCache(
                wrapped, 
                Duration.ofHours(1), true);
        
        identity = new Identity(USER_NAME, password, Identity.from("admin"));
        when(wrapped.getPasswordHasher()).thenReturn(hasher);
        when(wrapped.load(anyString())).thenReturn(identity);
    }
    
    @Test
    void testCallsWrapperOnce() {
        assertEquals(Status.VALID, subject.verify(USER_NAME, USER_PASS).getStatus());
        assertEquals(Status.VALID, subject.verify(USER_NAME, USER_PASS).getStatus());

        verify(wrapped, times(1)).load(anyString());
    }
    
    @Test
    void testCachesPassword() {
        long start = System.currentTimeMillis();
        assertEquals(Status.VALID, subject.verify(USER_NAME, USER_PASS).getStatus());
        final long time = System.currentTimeMillis() - start;

        start = System.currentTimeMillis();
        assertEquals(Status.VALID, subject.verify(USER_NAME, USER_PASS).getStatus());
        start = System.currentTimeMillis() - start;

        verify(wrapped, times(1)).load(anyString());
        assertTrue(start * 2 < time);
    }

    @Test
    void testFallback() {
        subject = new IdentityStoreCache(
                wrapped, 
                Duration.ofMillis(1), true);

        assertEquals(Status.VALID, subject.verify(USER_NAME, USER_PASS).getStatus());
        
        when(wrapped.load(anyString())).thenThrow(new RuntimeException("nöö"));

        assertEquals(Status.VALID, subject.verify(USER_NAME, USER_PASS).getStatus());

    }
    
    @Test
    void testReloadOnFailedPassword() {
        assertEquals(Status.VALID, subject.verify(USER_NAME, USER_PASS).getStatus());
        
        identity = new Identity(USER_NAME, hasher.encode("fo1"), null);
        when(wrapped.load(anyString())).thenReturn(identity);
        
        assertEquals(Status.VALID, subject.verify(USER_NAME, "fo1").getStatus());
        assertEquals(null, subject.verify(USER_NAME, "fo1").getGroups());
        verify(wrapped, times(2)).load(anyString());
    }
    
    @Test
    void overTakeRawPassword() throws Exception {
        subject = new IdentityStoreCache(
                wrapped, 
                Duration.ofNanos(1), true);
        
        assertEquals(Status.VALID, subject.verify(USER_NAME, USER_PASS).getStatus());
        assertEquals(USER_PASS, ((CachedIdentity)subject.loadWithFallbackToCache(USER_NAME)).getRawPassword());
        
        // we should overtake it
        Thread.sleep(1);
        assertEquals(USER_PASS, ((CachedIdentity)subject.loadWithFallbackToCache(USER_NAME)).getRawPassword());
        
        // if the password is changed we should not overtake the password anymore
        identity = new Identity(USER_NAME, hasher.encode("foobar"), Identity.from("admin"));
        when(wrapped.load(anyString())).thenReturn(identity);
        assertNull(((CachedIdentity)subject.loadWithFallbackToCache(USER_NAME)).getRawPassword());
        
        assertEquals(Status.VALID, subject.verify(USER_NAME, "foobar").getStatus());
        assertEquals(Status.INVALID_PASSWORD, subject.verify(USER_NAME, USER_PASS).getStatus());
    }
}

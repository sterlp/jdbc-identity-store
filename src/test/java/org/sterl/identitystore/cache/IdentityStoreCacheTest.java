package org.sterl.identitystore.cache;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
import org.sterl.identitystore.api.VerificationResult;
import org.sterl.identitystore.api.VerificationResult.Status;

public class IdentityStoreCacheTest {

    private static final String USER_NAME = "user";
    private static final String USER_PASS = "pass";

    final BCryptPbkdf2PasswordHash hasher = new BCryptPbkdf2PasswordHash();
    final String password = hasher.encode(USER_PASS);
    IdentityStore wrapped;
    CachedIdentityStore subject;
    Identity identity;
    
    @BeforeEach
    void before() {
        wrapped = mock(IdentityStore.class);

        subject = new CachedIdentityStore(
                wrapped, 
                Duration.ofHours(1), true);
        
        identity = new Identity(USER_NAME, password, Identity.from("admin"));
        when(wrapped.getPasswordHasher()).thenReturn(hasher);
        when(wrapped.load(anyString())).thenReturn(identity);
    }
    
    @Test
    void testCallsWrapperOnce() {
        VerificationResult verify = subject.verify(USER_NAME, USER_PASS);
        assertEquals(Status.VALID, verify.getStatus());
        assertFalse(verify.isCacheHit());
        
        verify = subject.verify(USER_NAME, USER_PASS);
        assertEquals(Status.VALID, verify.getStatus());
        assertTrue(verify.isCacheHit());

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
    void testFallback() throws Exception {
        subject = new CachedIdentityStore(
                wrapped, 
                Duration.ofMillis(2), true);

        assertFalse(subject.verify(USER_NAME, USER_PASS).isCacheHit());
        assertEquals(Status.VALID, subject.verify(USER_NAME, USER_PASS).getStatus());
        assertNull(subject.verify(USER_NAME, USER_PASS).getSuppressedError());
        
        final RuntimeException problem = new RuntimeException("nöö");
        when(wrapped.load(anyString())).thenThrow(problem);

        // still a cache hit ..., because fallback
        Thread.sleep(2);
        assertEquals(Status.VALID, subject.verify(USER_NAME, USER_PASS).getStatus());
        assertEquals(problem, subject.verify(USER_NAME, USER_PASS).getSuppressedError());
        assertTrue(subject.verify(USER_NAME, USER_PASS).isCacheHit());

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
        subject = new CachedIdentityStore(
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

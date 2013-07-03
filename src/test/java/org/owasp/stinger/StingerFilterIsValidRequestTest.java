/*
 * Copyright 2013 PCM, Inc.
 */
package org.owasp.stinger;

import org.junit.Test;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;
import org.owasp.stinger.http.MutableHttpRequest;

/**
 * Tests for MULTIPART VALIDATION BYPASS FIX
 * 
 * Only POST requests with Content-Type of "application/x-www-form-urlencoded"
 * should be accepted.
 * 
 * We should allow for extra media-type parameters.
 *
 * @author Edward Samson <Edward.Samson@pcm.com>
 */
public class StingerFilterIsValidRequestTest {

    @Test
    public void doNotAcceptMultipartFormEncodedPost() {
        MutableHttpRequest request = mock(MutableHttpRequest.class);
        when(request.getMethod()).thenReturn("POST");
        when(request.getContentType()).thenReturn("multipart/form-data");
        assertFalse(StingerFilter.isValidRequest(request));
    }

    @Test
    public void doNotAcceptPostWithNoContentType() {
        MutableHttpRequest request = mock(MutableHttpRequest.class);
        when(request.getMethod()).thenReturn("POST");
        when(request.getContentType()).thenReturn(null);
        assertFalse(StingerFilter.isValidRequest(request));
    }

    @Test
    public void doNotAcceptWeirdContentType() {
        MutableHttpRequest request = mock(MutableHttpRequest.class);
        when(request.getMethod()).thenReturn("POST");
        when(request.getContentType()).thenReturn("application/x-www-form-urlencodedweird");
        assertFalse(StingerFilter.isValidRequest(request));
    }

    @Test
    public void acceptUrlFormEncodedPost() {
        MutableHttpRequest request = mock(MutableHttpRequest.class);
        when(request.getMethod()).thenReturn("POST");
        when(request.getContentType()).thenReturn("application/x-www-form-urlencoded");
        assertTrue(StingerFilter.isValidRequest(request));
    }

    @Test
    public void acceptUrlFormEncodedPostUtf8() {
        MutableHttpRequest request = mock(MutableHttpRequest.class);
        when(request.getMethod()).thenReturn("POST");
        when(request.getContentType()).thenReturn("application/x-www-form-urlencoded; charset=UTF-8");
        assertTrue(StingerFilter.isValidRequest(request));
    }
}

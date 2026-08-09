/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.boot.faceid.authentication;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.boot.biz.userdetails.SecurityPrincipal;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.faceid.exception.AuthenticationFaceIDNotFoundException;
import org.springframework.security.boot.faceid.userdetails.FaceInfo;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link FaceIDAuthenticationProvider}.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("FaceIDAuthenticationProvider Tests")
class FaceIDAuthenticationProviderTest {

    private FaceRecognitionProvider faceRecognitionProvider;
    private UserDetailsServiceAdapter userDetailsService;
    private FaceIDAuthenticationProvider provider;

    @BeforeEach
    void setUp() {
        faceRecognitionProvider = mock(FaceRecognitionProvider.class);
        userDetailsService = mock(UserDetailsServiceAdapter.class);
        provider = new FaceIDAuthenticationProvider(faceRecognitionProvider, userDetailsService);
    }

    @Test
    @DisplayName("Constructor stores dependencies")
    void testConstructor() {
        assertThat(provider.getFaceRecognitionProvider()).isSameAs(faceRecognitionProvider);
        assertThat(provider.getUserDetailsService()).isSameAs(userDetailsService);
        assertThat(provider.getUserDetailsChecker()).isNotNull();
    }

    @Test
    @DisplayName("supports returns true for FaceIDAuthenticationToken")
    void testSupports() {
        assertThat(provider.supports(FaceIDAuthenticationToken.class)).isTrue();
        assertThat(provider.supports(Object.class)).isFalse();
    }

    @Test
    @DisplayName("setUserDetailsChecker replaces the default checker")
    void testSetUserDetailsChecker() {
        var checker = mock(org.springframework.security.core.userdetails.UserDetailsChecker.class);
        provider.setUserDetailsChecker(checker);
        assertThat(provider.getUserDetailsChecker()).isSameAs(checker);
    }

    @Test
    @DisplayName("authenticate throws BadCredentialsException when principal is null")
    void testAuthenticateNullPrincipal() {
        FaceIDAuthenticationToken token = new FaceIDAuthenticationToken(null);
        assertThatThrownBy(() -> provider.authenticate(token))
                .isInstanceOf(BadCredentialsException.class);
    }

    @Test
    @DisplayName("authenticate throws AuthenticationFaceIDNotFoundException when face info is null")
    void testAuthenticateNoFaceInfo() {
        InputStream stream = new ByteArrayInputStream("img".getBytes());
        FaceIDAuthenticationToken token = new FaceIDAuthenticationToken(stream);
        when(faceRecognitionProvider.loadFaceInfo(any())).thenReturn(null);
        assertThatThrownBy(() -> provider.authenticate(token))
                .isInstanceOf(AuthenticationFaceIDNotFoundException.class);
    }

    private void configureUserDetailsMock(UserDetails ud) {
        when(ud.getPassword()).thenReturn("pass");
        when(ud.isEnabled()).thenReturn(true);
        when(ud.isAccountNonExpired()).thenReturn(true);
        when(ud.isCredentialsNonExpired()).thenReturn(true);
        when(ud.isAccountNonLocked()).thenReturn(true);
    }

    @Test
    @DisplayName("authenticate returns authenticated token for SecurityPrincipal subclass")
    void testAuthenticateSuccessWithSecurityPrincipal() {
        InputStream stream = new ByteArrayInputStream("img".getBytes());
        FaceIDAuthenticationToken token = new FaceIDAuthenticationToken(stream);
        FaceInfo faceInfo = new FaceInfo();
        faceInfo.setFaceId("f1");
        when(faceRecognitionProvider.loadFaceInfo(any())).thenReturn(faceInfo);

        List<GrantedAuthority> authorities = Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"));
        SecurityPrincipal principal = mock(SecurityPrincipal.class);
        configureUserDetailsMock(principal);
        when(principal.getUsername()).thenReturn("user");
        doReturn(authorities).when(principal).getAuthorities();
        doReturn(principal).when(userDetailsService).loadUserDetails(any(Authentication.class));

        var result = provider.authenticate(token);
        assertThat(result).isNotNull();
        assertThat(result.isAuthenticated()).isTrue();
    }

    @Test
    @DisplayName("authenticate returns authenticated token for non-SecurityPrincipal UserDetails")
    void testAuthenticateSuccessWithPlainUserDetails() {
        InputStream stream = new ByteArrayInputStream("img".getBytes());
        FaceIDAuthenticationToken token = new FaceIDAuthenticationToken(stream);
        FaceInfo faceInfo = new FaceInfo();
        faceInfo.setFaceId("f1");
        when(faceRecognitionProvider.loadFaceInfo(any())).thenReturn(faceInfo);

        List<GrantedAuthority> authorities = Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"));
        UserDetails ud = mock(UserDetails.class);
        when(ud.getUsername()).thenReturn("user");
        configureUserDetailsMock(ud);
        doReturn(authorities).when(ud).getAuthorities();
        doReturn(ud).when(userDetailsService).loadUserDetails(any(Authentication.class));

        var result = provider.authenticate(token);
        assertThat(result).isNotNull();
        assertThat(result.isAuthenticated()).isTrue();
        assertThat(result.getPrincipal()).isEqualTo("user");
    }

    @Test
    @DisplayName("authenticate propagates UsernameNotFoundException from userDetailsService")
    void testAuthenticateUserNotFound() {
        InputStream stream = new ByteArrayInputStream("img".getBytes());
        FaceIDAuthenticationToken token = new FaceIDAuthenticationToken(stream);
        FaceInfo faceInfo = new FaceInfo();
        when(faceRecognitionProvider.loadFaceInfo(any())).thenReturn(faceInfo);
        doReturn(null).when(userDetailsService).loadUserDetails(any(Authentication.class));

        // loadUserDetails returns null -> loadUserByUsername is called -> throws
        assertThatThrownBy(() -> provider.authenticate(token))
                .isInstanceOf(Exception.class);
    }

    @Test
    @DisplayName("authenticate sets details from original token")
    void testAuthenticateSetsDetails() {
        InputStream stream = new ByteArrayInputStream("img".getBytes());
        FaceIDAuthenticationToken token = new FaceIDAuthenticationToken(stream);
        token.setDetails("some-detail");
        FaceInfo faceInfo = new FaceInfo();
        when(faceRecognitionProvider.loadFaceInfo(any())).thenReturn(faceInfo);

        UserDetails ud = mock(UserDetails.class);
        when(ud.getUsername()).thenReturn("user");
        configureUserDetailsMock(ud);
        doReturn(Collections.emptyList()).when(ud).getAuthorities();
        doReturn(ud).when(userDetailsService).loadUserDetails(any(Authentication.class));

        var result = provider.authenticate(token);
        assertThat(result.getDetails()).isEqualTo("some-detail");
    }

    @Test
    @DisplayName("authenticate with null authentication throws IllegalArgumentException")
    void testAuthenticateNull() {
        assertThatThrownBy(() -> provider.authenticate(null))
                .isInstanceOf(IllegalArgumentException.class);
    }
}

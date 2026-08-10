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
package org.springframework.security.boot;

import java.util.Collections;
import java.util.stream.Stream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.faceid.SecurityOpenIDAuthcProperties;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link SecurityFaceIDFilterConfiguration}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("SecurityFaceIDFilterConfiguration Tests")
class SecurityFaceIDFilterConfigurationTest {

    @Test
    @DisplayName("Filter configuration class can be instantiated")
    void testInstantiation() {
        SecurityFaceIDFilterConfiguration instance = new SecurityFaceIDFilterConfiguration();
        assertThat(instance).isNotNull();
    }

    @SuppressWarnings("unchecked")
    private SecurityFaceIDFilterConfiguration.FaceIDWebSecurityConfigurerAdapter createAdapter() {
        SecurityBizProperties bizProperties = new SecurityBizProperties();
        SecuritySessionMgtProperties sessionMgt = new SecuritySessionMgtProperties();
        SecurityOpenIDAuthcProperties authc = new SecurityOpenIDAuthcProperties();

        ObjectProvider localeProvider = mock(ObjectProvider.class);
        when(localeProvider.getIfAvailable()).thenReturn(null);

        ObjectProvider authProvider = mock(ObjectProvider.class);
        when(authProvider.stream()).thenReturn(Stream.empty());

        ObjectProvider listenerProvider = mock(ObjectProvider.class);
        when(listenerProvider.stream()).thenReturn(Stream.empty());

        ObjectProvider entryPointProvider = mock(ObjectProvider.class);
        when(entryPointProvider.stream()).thenReturn(Stream.empty());

        ObjectProvider successProvider = mock(ObjectProvider.class);
        when(successProvider.stream()).thenReturn(Stream.empty());

        ObjectProvider failureProvider = mock(ObjectProvider.class);
        when(failureProvider.stream()).thenReturn(Stream.empty());

        ObjectProvider rememberMeProvider = mock(ObjectProvider.class);
        when(rememberMeProvider.getIfAvailable()).thenReturn(null);

        ObjectProvider sessionProvider = mock(ObjectProvider.class);
        when(sessionProvider.getIfAvailable()).thenReturn(null);

        return new SecurityFaceIDFilterConfiguration.FaceIDWebSecurityConfigurerAdapter(
                bizProperties, sessionMgt, authc,
                localeProvider,
                authProvider,
                listenerProvider,
                entryPointProvider,
                successProvider,
                failureProvider,
                rememberMeProvider,
                sessionProvider
        );
    }

    @Test
    @DisplayName("Inner FaceIDWebSecurityConfigurerAdapter can be instantiated")
    void testInnerClassInstantiation() {
        var adapter = createAdapter();
        assertThat(adapter).isNotNull();
    }

    @Test
    @DisplayName("configure(HttpSecurity) configures the security filter chain")
    void testConfigureHttpSecurity() throws Exception {
        var adapter = createAdapter();

        // Set the authentication manager via reflection so authenticationManagerBean() works
        AuthenticationManager authManager = mock(AuthenticationManager.class);
        java.lang.reflect.Field field = WebSecurityBizConfigurerAdapter.class.getDeclaredField("authenticationManager");
        field.setAccessible(true);
        field.set(adapter, authManager);

        // Mock HttpSecurity to return itself for chained calls
        HttpSecurity http = mock(HttpSecurity.class);
        when(http.securityMatcher(org.mockito.ArgumentMatchers.any(String[].class))).thenReturn(http);
        when(http.securityMatcher(org.mockito.ArgumentMatchers.anyString())).thenReturn(http);
        when(http.exceptionHandling(org.mockito.ArgumentMatchers.any())).thenReturn(http);
        when(http.httpBasic(org.mockito.ArgumentMatchers.any())).thenReturn(http);
        when(http.addFilterBefore(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any())).thenReturn(http);
        when(http.cors(org.mockito.ArgumentMatchers.any())).thenReturn(http);
        when(http.csrf(org.mockito.ArgumentMatchers.any())).thenReturn(http);
        when(http.headers(org.mockito.ArgumentMatchers.any())).thenReturn(http);
        when(http.authorizeHttpRequests(org.mockito.ArgumentMatchers.any())).thenReturn(http);

        adapter.configure(http);
        assertThat(adapter).isNotNull();
    }
}

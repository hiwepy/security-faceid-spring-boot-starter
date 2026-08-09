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

import java.util.Collections;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link FaceIDAuthenticationToken}.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("FaceIDAuthenticationToken Tests")
class FaceIDAuthenticationTokenTest {

    @Test
    @DisplayName("Unauthenticated token has null authorities and is not authenticated")
    void testUnauthenticatedToken() {
        FaceIDAuthenticationToken token = new FaceIDAuthenticationToken("principal");
        assertThat(token).isNotNull();
        assertThat(token.getPrincipal()).isEqualTo("principal");
        assertThat(token.getCredentials()).isNull();
        assertThat(token.isAuthenticated()).isFalse();
        assertThat(token.getAuthorities()).isEmpty();
    }

    @Test
    @DisplayName("Authenticated token carries principal, credentials and authorities")
    void testAuthenticatedToken() {
        FaceIDAuthenticationToken token = new FaceIDAuthenticationToken(
                "user", "pass", Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
        assertThat(token.getPrincipal()).isEqualTo("user");
        assertThat(token.getCredentials()).isEqualTo("pass");
        assertThat(token.isAuthenticated()).isTrue();
        assertThat(token.getAuthorities()).hasSize(1);
    }

    @Test
    @DisplayName("setAuthenticated(true) throws IllegalArgumentException")
    void testSetAuthenticatedTrueThrows() {
        FaceIDAuthenticationToken token = new FaceIDAuthenticationToken("p");
        assertThatThrownBy(() -> token.setAuthenticated(true))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("setAuthenticated(false) is accepted")
    void testSetAuthenticatedFalse() {
        FaceIDAuthenticationToken token = new FaceIDAuthenticationToken("p");
        token.setAuthenticated(false);
        assertThat(token.isAuthenticated()).isFalse();
    }

    @Test
    @DisplayName("eraseCredentials nulls the credentials field")
    void testEraseCredentials() {
        FaceIDAuthenticationToken token = new FaceIDAuthenticationToken(
                "user", "secret", Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
        assertThat(token.getCredentials()).isEqualTo("secret");
        token.eraseCredentials();
        assertThat(token.getCredentials()).isNull();
    }
}

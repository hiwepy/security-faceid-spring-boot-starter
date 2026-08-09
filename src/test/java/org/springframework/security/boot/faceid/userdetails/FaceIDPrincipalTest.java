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
package org.springframework.security.boot.faceid.userdetails;

import java.util.Collections;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link FaceIDPrincipal}.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("FaceIDPrincipal Tests")
class FaceIDPrincipalTest {

    @Test
    @DisplayName("Constructor with varargs roles initialises fields correctly")
    void testConstructorWithRoles() {
        FaceIDPrincipal principal = new FaceIDPrincipal("user", "pass", "ADMIN", "USER");
        assertThat(principal.getUsername()).isEqualTo("user");
        assertThat(principal.getPassword()).isEqualTo("pass");
        assertThat(principal.getAuthorities()).hasSize(2);
    }

    @Test
    @DisplayName("Constructor with authorities collection initialises fields correctly")
    void testConstructorWithAuthorities() {
        FaceIDPrincipal principal = new FaceIDPrincipal("user2", "pass2",
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
        assertThat(principal.getUsername()).isEqualTo("user2");
        assertThat(principal.getAuthorities()).hasSize(1);
    }

    @Test
    @DisplayName("Constructor with account-status flags initialises fields correctly")
    void testConstructorWithAccountStatus() {
        FaceIDPrincipal principal = new FaceIDPrincipal("user3", "pass3",
                true, true, true, true,
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_ADMIN")));
        assertThat(principal.getUsername()).isEqualTo("user3");
        assertThat(principal.isEnabled()).isTrue();
        assertThat(principal.isAccountNonExpired()).isTrue();
        assertThat(principal.isCredentialsNonExpired()).isTrue();
        assertThat(principal.isAccountNonLocked()).isTrue();
    }

    @Test
    @DisplayName("faceId getter and setter work correctly")
    void testFaceIdProperty() {
        FaceIDPrincipal principal = new FaceIDPrincipal("user", "pass", "USER");
        principal.setFaceId("fid-001");
        assertThat(principal.getFaceId()).isEqualTo("fid-001");
    }

    @Test
    @DisplayName("face getter and setter work correctly")
    void testFaceProperty() {
        FaceIDPrincipal principal = new FaceIDPrincipal("user", "pass", "USER");
        principal.setFace("base64data");
        assertThat(principal.getFace()).isEqualTo("base64data");
    }

    @Test
    @DisplayName("faceType getter and setter work correctly")
    void testFaceTypeProperty() {
        FaceIDPrincipal principal = new FaceIDPrincipal("user", "pass", "USER");
        principal.setFaceType("LIVE");
        assertThat(principal.getFaceType()).isEqualTo("LIVE");
    }

    @Test
    @DisplayName("faceToken getter and setter work correctly")
    void testFaceTokenProperty() {
        FaceIDPrincipal principal = new FaceIDPrincipal("user", "pass", "USER");
        principal.setFaceToken("token-abc");
        assertThat(principal.getFaceToken()).isEqualTo("token-abc");
    }

    @Test
    @DisplayName("Default face fields are null")
    void testDefaultFaceFieldsAreNull() {
        FaceIDPrincipal principal = new FaceIDPrincipal("user", "pass", "USER");
        assertThat(principal.getFaceId()).isNull();
        assertThat(principal.getFace()).isNull();
        assertThat(principal.getFaceType()).isNull();
        assertThat(principal.getFaceToken()).isNull();
    }
}

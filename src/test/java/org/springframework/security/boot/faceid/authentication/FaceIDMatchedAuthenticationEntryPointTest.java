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

import java.io.IOException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.boot.faceid.exception.AuthenticationFaceIDNotFoundException;
import org.springframework.security.boot.faceid.exception.AuthenticationFaceNotFoundException;
import org.springframework.security.core.AuthenticationException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link FaceIDMatchedAuthenticationEntryPoint}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("FaceIDMatchedAuthenticationEntryPoint Tests")
class FaceIDMatchedAuthenticationEntryPointTest {

    private final FaceIDMatchedAuthenticationEntryPoint entryPoint = new FaceIDMatchedAuthenticationEntryPoint();

    @Test
    @DisplayName("Instance can be created via constructor")
    void testInstantiation() {
        assertThat(entryPoint).isNotNull();
    }

    @Test
    @DisplayName("supports returns true for AuthenticationFaceNotFoundException")
    void testSupportsFaceNotFound() {
        assertThat(entryPoint.supports(new AuthenticationFaceNotFoundException("no face"))).isTrue();
    }

    @Test
    @DisplayName("supports returns true for AuthenticationFaceIDNotFoundException")
    void testSupportsFaceIdNotFound() {
        assertThat(entryPoint.supports(new AuthenticationFaceIDNotFoundException("no id"))).isTrue();
    }

    @Test
    @DisplayName("supports returns false for generic AuthenticationException")
    void testSupportsGenericException() {
        assertThat(entryPoint.supports(new AuthenticationException("generic") {})).isFalse();
    }

    @Test
    @DisplayName("commence writes JSON for AuthenticationFaceNotFoundException")
    void testCommenceFaceNotFound() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        entryPoint.commence(request, response, new AuthenticationFaceNotFoundException("no face"));
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getContentType()).startsWith("application/json");
        assertThat(response.getContentAsString()).contains("code");
    }

    @Test
    @DisplayName("commence writes JSON for AuthenticationFaceIDNotFoundException")
    void testCommenceFaceIdNotFound() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        entryPoint.commence(request, response, new AuthenticationFaceIDNotFoundException("no id"));
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getContentAsString()).contains("code");
    }

    @Test
    @DisplayName("commence writes JSON for generic exception")
    void testCommenceGenericException() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        entryPoint.commence(request, response, new AuthenticationException("generic") {});
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getContentAsString()).contains("code");
    }
}

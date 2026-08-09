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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link FaceIDAuthenticationProcessingFilter}.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("FaceIDAuthenticationProcessingFilter Tests")
class FaceIDAuthenticationProcessingFilterTest {

    @Test
    @DisplayName("Instance can be created via constructor")
    void testInstantiation() {
        FaceIDAuthenticationProcessingFilter instance = new FaceIDAuthenticationProcessingFilter();
        assertThat(instance).isNotNull();
    }

    @Test
    @DisplayName("Default face parameter is 'face'")
    void testDefaultFaceParameter() {
        FaceIDAuthenticationProcessingFilter filter = new FaceIDAuthenticationProcessingFilter();
        assertThat(filter.getFaceParameter()).isEqualTo("face");
    }

    @Test
    @DisplayName("Face parameter can be changed")
    void testSetFaceParameter() {
        FaceIDAuthenticationProcessingFilter filter = new FaceIDAuthenticationProcessingFilter();
        filter.setFaceParameter("myFace");
        assertThat(filter.getFaceParameter()).isEqualTo("myFace");
    }

    @Test
    @DisplayName("Default postOnly is true")
    void testDefaultPostOnly() {
        FaceIDAuthenticationProcessingFilter filter = new FaceIDAuthenticationProcessingFilter();
        assertThat(filter.isPostOnly()).isTrue();
    }

    @Test
    @DisplayName("postOnly can be set to false")
    void testSetPostOnly() {
        FaceIDAuthenticationProcessingFilter filter = new FaceIDAuthenticationProcessingFilter();
        filter.setPostOnly(false);
        assertThat(filter.isPostOnly()).isFalse();
    }

    @Test
    @DisplayName("SPRING_SECURITY_FORM_FACE_KEY constant equals 'face'")
    void testFormFaceKey() {
        assertThat(FaceIDAuthenticationProcessingFilter.SPRING_SECURITY_FORM_FACE_KEY).isEqualTo("face");
    }
}

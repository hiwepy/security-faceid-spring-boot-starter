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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link FaceInfo}.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("FaceInfo Tests")
class FaceInfoTest {

    @Test
    @DisplayName("Default instance has null fields")
    void testDefaultInstance() {
        FaceInfo info = new FaceInfo();
        assertThat(info.getFaceId()).isNull();
        assertThat(info.getFace()).isNull();
        assertThat(info.getFaceType()).isNull();
        assertThat(info.getFaceToken()).isNull();
    }

    @Test
    @DisplayName("Setters and getters work correctly")
    void testSettersAndGetters() {
        FaceInfo info = new FaceInfo();
        info.setFaceId("f1");
        info.setFace("base64");
        info.setFaceType("LIVE");
        info.setFaceToken("tok");
        assertThat(info.getFaceId()).isEqualTo("f1");
        assertThat(info.getFace()).isEqualTo("base64");
        assertThat(info.getFaceType()).isEqualTo("LIVE");
        assertThat(info.getFaceToken()).isEqualTo("tok");
    }

    @Test
    @DisplayName("equals and hashCode are consistent")
    void testEqualsAndHashCode() {
        FaceInfo a = new FaceInfo();
        a.setFaceId("f1");
        a.setFace("img");
        a.setFaceType("LIVE");
        a.setFaceToken("tok");
        FaceInfo b = new FaceInfo();
        b.setFaceId("f1");
        b.setFace("img");
        b.setFaceType("LIVE");
        b.setFaceToken("tok");
        assertThat(a).isEqualTo(b);
        assertThat(a.hashCode()).isEqualTo(b.hashCode());
    }

    @Test
    @DisplayName("equals returns false for different objects")
    void testNotEquals() {
        FaceInfo a = new FaceInfo();
        a.setFaceId("f1");
        FaceInfo b = new FaceInfo();
        b.setFaceId("f2");
        assertThat(a).isNotEqualTo(b);
        assertThat(a).isNotEqualTo(null);
        assertThat(a).isNotEqualTo("string");
    }

    @Test
    @DisplayName("toString contains field values")
    void testToString() {
        FaceInfo info = new FaceInfo();
        info.setFaceId("f1");
        assertThat(info.toString()).contains("f1").contains("FaceInfo");
    }
}

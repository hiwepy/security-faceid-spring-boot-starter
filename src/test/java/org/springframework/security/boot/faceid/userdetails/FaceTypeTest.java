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
 * Unit tests for {@link FaceType}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("FaceType Tests")
class FaceTypeTest {

    @Test
    @DisplayName("LIVE enum constant exists")
    void testLive() {
        assertThat(FaceType.LIVE).isNotNull();
        assertThat(FaceType.valueOf("LIVE")).isEqualTo(FaceType.LIVE);
    }

    @Test
    @DisplayName("IDCARD enum constant exists")
    void testIdcard() {
        assertThat(FaceType.IDCARD).isNotNull();
        assertThat(FaceType.valueOf("IDCARD")).isEqualTo(FaceType.IDCARD);
    }

    @Test
    @DisplayName("WATERMARK enum constant exists")
    void testWatermark() {
        assertThat(FaceType.WATERMARK).isNotNull();
        assertThat(FaceType.valueOf("WATERMARK")).isEqualTo(FaceType.WATERMARK);
    }

    @Test
    @DisplayName("CERT enum constant exists")
    void testCert() {
        assertThat(FaceType.CERT).isNotNull();
        assertThat(FaceType.valueOf("CERT")).isEqualTo(FaceType.CERT);
    }

    @Test
    @DisplayName("values() returns all four constants")
    void testValues() {
        assertThat(FaceType.values()).hasSize(4);
    }
}

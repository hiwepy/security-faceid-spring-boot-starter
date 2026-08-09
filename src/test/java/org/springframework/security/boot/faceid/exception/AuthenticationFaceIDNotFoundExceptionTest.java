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
package org.springframework.security.boot.faceid.exception;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link AuthenticationFaceIDNotFoundException}.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("AuthenticationFaceIDNotFoundException Tests")
class AuthenticationFaceIDNotFoundExceptionTest {

    @Test
    @DisplayName("Constructor with message sets message")
    void testConstructorWithMessage() {
        AuthenticationFaceIDNotFoundException ex = new AuthenticationFaceIDNotFoundException("not found");
        assertThat(ex.getMessage()).isEqualTo("not found");
        assertThat(ex.getCause()).isNull();
    }

    @Test
    @DisplayName("Constructor with message and cause sets both")
    void testConstructorWithMessageAndCause() {
        RuntimeException cause = new RuntimeException("root");
        AuthenticationFaceIDNotFoundException ex = new AuthenticationFaceIDNotFoundException("not found", cause);
        assertThat(ex.getMessage()).isEqualTo("not found");
        assertThat(ex.getCause()).isEqualTo(cause);
    }
}

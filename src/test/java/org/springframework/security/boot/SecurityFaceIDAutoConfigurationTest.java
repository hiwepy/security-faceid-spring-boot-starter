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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.faceid.authentication.FaceRecognitionProvider;
import org.springframework.security.boot.faceid.userdetails.FaceInfo;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Unit tests for {{ @link SecurityFaceIDAutoConfiguration }}.
 *
 * <p>Verifies the auto-configuration activates under the expected conditions
 * and exposes its declared beans.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("SecurityFaceIDAutoConfiguration Tests")
class SecurityFaceIDAutoConfigurationTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner();

    @Test
    @DisplayName("Auto-configuration class can be instantiated")
    void testInstantiation() {
        SecurityFaceIDAutoConfiguration configuration = new SecurityFaceIDAutoConfiguration();
        assertThat(configuration).isNotNull();
    }

    @Test
    @DisplayName("Auto-configuration loads when 'spring.security.faceid.enabled=true'")
    void testLoadsWhenEnabledPropertySet() {
        runner.withUserConfiguration(TestConfig.class, SecurityFaceIDAutoConfiguration.class)
                .withPropertyValues("spring.security.faceid.enabled=true")
                .run(context -> assertThat(context).hasSingleBean(SecurityFaceIDAutoConfiguration.class));
    }

    /**
     * Minimal test configuration that supplies the beans required by
     * {@link SecurityFaceIDAutoConfiguration}.
     */
    @org.springframework.context.annotation.Configuration
    static class TestConfig {

        @Bean
        public FaceRecognitionProvider faceRecognitionProvider() {
            return authentication -> null;
        }

        @Bean
        public UserDetailsServiceAdapter userDetailsServiceAdapter() {
            return new UserDetailsServiceAdapter() {
                @Override
                public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
                    return mock(UserDetails.class);
                }
            };
        }
    }

    @Test
    @DisplayName("Auto-configuration is absent when property is not set")
    void testNotLoadedWhenPropertyAbsent() {
        runner.withUserConfiguration(SecurityFaceIDAutoConfiguration.class)
                .run(context -> assertThat(context).doesNotHaveBean(SecurityFaceIDAutoConfiguration.class));
    }
}

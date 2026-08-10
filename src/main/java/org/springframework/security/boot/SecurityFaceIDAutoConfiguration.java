package org.springframework.security.boot;

import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.faceid.authentication.FaceIDAuthenticationProvider;
import org.springframework.security.boot.faceid.authentication.FaceIDMatchedAuthenticationEntryPoint;
import org.springframework.security.boot.faceid.authentication.FaceIDMatchedAuthenticationFailureHandler;
import org.springframework.security.boot.faceid.authentication.FaceRecognitionProvider;

/**
 * Auto-configuration for face-ID authentication. <p>Activated when
 * {@code spring.security.faceid.enabled=true}, it registers the face-ID authentication
 * provider, entry point and failure handler beans.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@Configuration
@AutoConfigureBefore(SecurityBizAutoConfiguration.class)
@ConditionalOnProperty(prefix = SecurityFaceIDProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityFaceIDProperties.class })
public class SecurityFaceIDAutoConfiguration {

	/**
	 * Registers the face-ID authentication entry point.
	 * @return a new {@link FaceIDMatchedAuthenticationEntryPoint}
	 */
	@Bean
	public FaceIDMatchedAuthenticationEntryPoint idcMatchedAuthenticationEntryPoint() {
		return new FaceIDMatchedAuthenticationEntryPoint();
	}

	/**
	 * Registers the face-ID authentication failure handler.
	 * @return a new {@link FaceIDMatchedAuthenticationFailureHandler}
	 */
	@Bean
	public FaceIDMatchedAuthenticationFailureHandler idcMatchedAuthenticationFailureHandler() {
		return new FaceIDMatchedAuthenticationFailureHandler();
	}

	/**
	 * Registers the face-ID authentication provider.
	 * @param faceRecognitionProvider the face-recognition strategy
	 * @param userDetailsService the user-details adapter
	 * @return a new {@link FaceIDAuthenticationProvider}
	 */
	@Bean
	public FaceIDAuthenticationProvider idcCodeAuthenticationProvider(FaceRecognitionProvider faceRecognitionProvider,
			UserDetailsServiceAdapter userDetailsService) {
		return new FaceIDAuthenticationProvider(faceRecognitionProvider, userDetailsService);
	}

}

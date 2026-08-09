package org.springframework.security.boot;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

/**
 * Configuration properties for face-ID security. <p>Binds the {@code spring.security.faceid}
 * prefix and controls whether face-ID authentication is enabled.</p>
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@ConfigurationProperties(prefix = SecurityFaceIDProperties.PREFIX)
@Getter
@Setter
@ToString
public class SecurityFaceIDProperties {

	public static final String PREFIX = "spring.security.faceid";

	/** Whether face-ID authentication is enabled. */
	private boolean enabled = false;

}

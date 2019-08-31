package org.springframework.security.boot;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.faceid.authentication.FaceIDAuthenticationProvider;
import org.springframework.security.boot.faceid.authentication.FaceIDMatchedAuthenticationEntryPoint;
import org.springframework.security.boot.faceid.authentication.FaceIDMatchedAuthenticationFailureHandler;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@AutoConfigureBefore(SecurityBizAutoConfiguration.class)
@ConditionalOnProperty(prefix = SecurityFaceIDProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityFaceIDProperties.class })
public class SecurityFaceIDAutoConfiguration {

	@Autowired
	private SecurityFaceIDProperties openidProperties;

	@Bean
	public FaceIDMatchedAuthenticationEntryPoint idcMatchedAuthenticationEntryPoint() {
		return new FaceIDMatchedAuthenticationEntryPoint();
	}
	
	@Bean
	public FaceIDMatchedAuthenticationFailureHandler idcMatchedAuthenticationFailureHandler() {
		return new FaceIDMatchedAuthenticationFailureHandler();
	}
	 
	@Bean
	public FaceIDAuthenticationProvider idcCodeAuthenticationProvider(
			UserDetailsServiceAdapter userDetailsService, PasswordEncoder passwordEncoder) {
		return new FaceIDAuthenticationProvider(userDetailsService, passwordEncoder);
	}
    
}

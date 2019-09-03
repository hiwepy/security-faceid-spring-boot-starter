package org.springframework.security.boot;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.context.EnvironmentAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationSuccessHandler;
import org.springframework.security.boot.faceid.authentication.FaceIDAuthenticationProcessingFilter;
import org.springframework.security.boot.faceid.authentication.FaceIDAuthenticationProvider;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

@Configuration
@AutoConfigureBefore(name = { 
	"org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration"
})
@ConditionalOnWebApplication
@ConditionalOnProperty(prefix = SecurityFaceIDProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityFaceIDProperties.class, SecurityBizProperties.class, ServerProperties.class })
public class SecurityFaceIDFilterConfiguration implements ApplicationEventPublisherAware, EnvironmentAware {


	private ApplicationEventPublisher eventPublisher;
	private Environment environment;
 
	
	@Configuration
	@EnableConfigurationProperties({ SecurityFaceIDProperties.class, SecurityBizProperties.class })
	static class FaceIDWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

	    private final FaceIDAuthenticationFilter openIDAuthenticationFilter;
	    private final FaceIDAuthenticationProvider openIDAuthenticationProvider;
	    private final PostRequestAuthenticationSuccessHandler authenticationSuccessHandler;
	    private final PostRequestAuthenticationFailureHandler authenticationFailureHandler;
		private final SecurityFaceIDProperties faceIDProperties;
		private final SessionAuthenticationStrategy sessionAuthenticationStrategy;
	
		public FaceIDWebSecurityConfigurerAdapter(
				SecurityFaceIDProperties faceIDProperties,
				ObjectProvider<FaceIDAuthenticationFilter> openIDAuthenticationFilterProvider,
				ObjectProvider<FaceIDAuthenticationProvider> openIDAuthenticationProvider,
				ObjectProvider<FaceIDAuthcUserDetailsService> openIDAuthcUserDetailsService, 
				ObjectProvider<FaceIDConsumer> consumerProvider,
				ObjectProvider<ConsumerManager> consumerManagerProvider,
				@Qualifier("jwtAuthenticationSuccessHandler") ObjectProvider<PostRequestAuthenticationSuccessHandler> authenticationSuccessHandler,
   				@Qualifier("jwtAuthenticationFailureHandler") ObjectProvider<PostRequestAuthenticationFailureHandler> authenticationFailureHandler,
				ObjectProvider<SessionAuthenticationStrategy> sessionAuthenticationStrategyProvider) {
			this.faceIDProperties = faceIDProperties;
			this.openIDAuthenticationFilter = openIDAuthenticationFilterProvider.getIfAvailable();
			this.openIDAuthenticationProvider = openIDAuthenticationProvider.getIfAvailable();
			this.openIDAuthcUserDetailsService = openIDAuthcUserDetailsService.getIfAvailable();
			this.consumer = consumerProvider.getIfAvailable();
			this.consumerManager = consumerManagerProvider.getIfAvailable();
			this.authenticationSuccessHandler = authenticationSuccessHandler.getIfAvailable();
   			this.authenticationFailureHandler = authenticationFailureHandler.getIfAvailable();
			this.sessionAuthenticationStrategy = sessionAuthenticationStrategyProvider.getIfAvailable();
		}

		@Bean
		public FaceIDAuthenticationProcessingFilter faceIDAuthenticationProcessingFilter() throws Exception {
	    	
	        JwtAuthenticationProcessingFilter authcFilter = new JwtAuthenticationProcessingFilter(objectMapper);
	        
	        authcFilter.setCaptchaParameter(jwtAuthcProperties.getCaptcha().getParamName());
			// 是否验证码必填
			authcFilter.setCaptchaRequired(jwtAuthcProperties.getCaptcha().isRequired());
			// 登陆失败重试次数，超出限制需要输入验证码
			authcFilter.setRetryTimesWhenAccessDenied(jwtAuthcProperties.getCaptcha().getRetryTimesWhenAccessDenied());
			// 验证码解析器
			authcFilter.setCaptchaResolver(captchaResolver);
			// 认证失败计数器
			authcFilter.setFailureCounter(authenticatingFailureCounter);

			authcFilter.setAllowSessionCreation(jwtProperties.getSessionMgt().isAllowSessionCreation());
			authcFilter.setApplicationEventPublisher(eventPublisher);
			authcFilter.setAuthenticationFailureHandler(authenticationFailureHandler);
			authcFilter.setAuthenticationManager(authenticationManager);
			authcFilter.setAuthenticationSuccessHandler(authenticationSuccessHandler);
			authcFilter.setContinueChainBeforeSuccessfulAuthentication(jwtAuthcProperties.isContinueChainBeforeSuccessfulAuthentication());
			if (StringUtils.hasText(jwtAuthcProperties.getLoginUrlPatterns())) {
				authcFilter.setFilterProcessesUrl(jwtAuthcProperties.getLoginUrlPatterns());
			}
			//authcFilter.setMessageSource(messageSource);
			authcFilter.setUsernameParameter(jwtAuthcProperties.getUsernameParameter());
			authcFilter.setPasswordParameter(jwtAuthcProperties.getPasswordParameter());
			authcFilter.setPostOnly(jwtAuthcProperties.isPostOnly());
			authcFilter.setRememberMeServices(rememberMeServices);
			authcFilter.setRetryTimesKeyAttribute(jwtAuthcProperties.getRetryTimesKeyAttribute());
			authcFilter.setRetryTimesWhenAccessDenied(jwtAuthcProperties.getRetryTimesWhenAccessDenied());
			authcFilter.setSessionAuthenticationStrategy(sessionAuthenticationStrategy);
			
	        return authcFilter;
	    }
		
	    @Override
	    protected void configure(AuthenticationManagerBuilder auth) {
	        auth.authenticationProvider(openIDAuthenticationProvider);
	    }
		
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			
			http.openidLogin()
				.attributeExchange(properties.getAuthc().getIdentifierPattern())
				.attribute(attribute)
				.and()
				.authenticationUserDetailsService(this.openIDAuthcUserDetailsService)
				.consumer(this.consumer)
				.consumerManager(this.consumerManager)
				.defaultSuccessUrl(properties.getAuthc().getSuccessUrl())
				.failureHandler(this.authenticationFailureHandler)
				.failureUrl(properties.getAuthc().getFailureUrl())
				.loginProcessingUrl(properties.getAuthc().getLoginUrl())
				.successHandler(this.authenticationSuccessHandler)
				.and()
				.sessionManagement()
				.sessionAuthenticationStrategy(sessionAuthenticationStrategy)
	            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
	            .and()
	            .addFilterBefore(openIDAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
			
		}

	}
	
	@Override
	public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
		this.eventPublisher = applicationEventPublisher;
	}

	@Override
	public void setEnvironment(Environment environment) {
		this.environment = environment;
	}
	
}

package org.springframework.security.boot;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.PropertyMapper;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.context.EnvironmentAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationSuccessHandler;
import org.springframework.security.boot.faceid.authentication.FaceIDAuthenticationProcessingFilter;
import org.springframework.security.boot.faceid.authentication.FaceIDAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.RememberMeServices;
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

		private final SecurityBizProperties bizProperties;
	    private final SecurityFaceIDProperties faceIDProperties;
	    
	    private final AuthenticationManager authenticationManager;
	    private final RememberMeServices rememberMeServices;
	    
	    private final FaceIDAuthenticationProvider faceIDAuthenticationProvider;
	    private final PostRequestAuthenticationSuccessHandler authenticationSuccessHandler;
	    private final PostRequestAuthenticationFailureHandler authenticationFailureHandler;
		private final SessionAuthenticationStrategy sessionAuthenticationStrategy;
	
		public FaceIDWebSecurityConfigurerAdapter(
				
				ObjectProvider<AuthenticationManager> authenticationManagerProvider,
   				ObjectProvider<RememberMeServices> rememberMeServicesProvider,
   				
				SecurityBizProperties bizProperties,
				SecurityFaceIDProperties faceIDProperties,
				ObjectProvider<FaceIDAuthenticationProvider> faceIDAuthenticationProvider,
				@Qualifier("jwtAuthenticationSuccessHandler") ObjectProvider<PostRequestAuthenticationSuccessHandler> authenticationSuccessHandler,
   				ObjectProvider<PostRequestAuthenticationFailureHandler> authenticationFailureHandler,
				ObjectProvider<SessionAuthenticationStrategy> sessionAuthenticationStrategyProvider) {
			
			this.bizProperties = bizProperties;
			this.faceIDProperties = faceIDProperties;
			
			this.authenticationManager = authenticationManagerProvider.getIfAvailable();
			this.rememberMeServices = rememberMeServicesProvider.getIfAvailable();
			
			this.faceIDAuthenticationProvider = faceIDAuthenticationProvider.getIfAvailable();
			this.authenticationSuccessHandler = authenticationSuccessHandler.getIfAvailable();
   			this.authenticationFailureHandler = authenticationFailureHandler.getIfAvailable();
			this.sessionAuthenticationStrategy = sessionAuthenticationStrategyProvider.getIfAvailable();
		}

		public FaceIDAuthenticationProcessingFilter authenticationProcessingFilter() throws Exception {
	    	
			FaceIDAuthenticationProcessingFilter authenticationFilter = new FaceIDAuthenticationProcessingFilter();
			
			/**
			 * 批量设置参数
			 */
			PropertyMapper map = PropertyMapper.get().alwaysApplyingWhenNonNull();
			
			map.from(bizProperties.getSessionMgt().isAllowSessionCreation()).to(authenticationFilter::setAllowSessionCreation);
			
			map.from(authenticationManager).to(authenticationFilter::setAuthenticationManager);
			map.from(authenticationSuccessHandler).to(authenticationFilter::setAuthenticationSuccessHandler);
			map.from(authenticationFailureHandler).to(authenticationFilter::setAuthenticationFailureHandler);
			
			map.from(faceIDProperties.getAuthc().getLoginUrlPatterns()).to(authenticationFilter::setFilterProcessesUrl);
			map.from(faceIDProperties.getAuthc().isPostOnly()).to(authenticationFilter::setPostOnly);
			map.from(rememberMeServices).to(authenticationFilter::setRememberMeServices);
			map.from(sessionAuthenticationStrategy).to(authenticationFilter::setSessionAuthenticationStrategy);
			map.from(faceIDProperties.getAuthc().isContinueChainBeforeSuccessfulAuthentication()).to(authenticationFilter::setContinueChainBeforeSuccessfulAuthentication);
			
	        return authenticationFilter;
	    }
		
	    @Override
	    protected void configure(AuthenticationManagerBuilder auth) {
	        auth.authenticationProvider(faceIDAuthenticationProvider);
	    }
		
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			
			http.addFilterBefore(authenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class);
			
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

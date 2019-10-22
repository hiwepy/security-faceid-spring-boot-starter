package org.springframework.security.boot;

import java.util.Arrays;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.PropertyMapper;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.context.EnvironmentAware;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationSuccessHandler;
import org.springframework.security.boot.faceid.authentication.FaceIDAuthenticationProcessingFilter;
import org.springframework.security.boot.faceid.authentication.FaceIDAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.web.cors.CorsConfigurationSource;

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
	@Order(SecurityProperties.DEFAULT_FILTER_ORDER + 3)
	static class FaceIDWebSecurityConfigurerAdapter extends SecurityBizConfigurerAdapter {

		private final SecurityBizProperties bizProperties;
	    private final SecurityFaceIDProperties authcProperties;
	    
	    private final AuthenticationManager authenticationManager;
	    private final RememberMeServices rememberMeServices;
	    
	    private final FaceIDAuthenticationProvider authenticationProvider;
	    private final PostRequestAuthenticationSuccessHandler authenticationSuccessHandler;
	    private final PostRequestAuthenticationFailureHandler authenticationFailureHandler;
		private final SessionAuthenticationStrategy sessionAuthenticationStrategy;
	
		public FaceIDWebSecurityConfigurerAdapter(
				
				ObjectProvider<AuthenticationManager> authenticationManagerProvider,
   				ObjectProvider<RememberMeServices> rememberMeServicesProvider,
   				
				SecurityBizProperties bizProperties,
				SecurityFaceIDProperties faceIDProperties,
				ObjectProvider<CsrfTokenRepository> csrfTokenRepositoryProvider,
   				ObjectProvider<CorsConfigurationSource> configurationSourceProvider,
				ObjectProvider<FaceIDAuthenticationProvider> faceIDAuthenticationProvider,
				@Qualifier("jwtAuthenticationSuccessHandler") ObjectProvider<PostRequestAuthenticationSuccessHandler> authenticationSuccessHandler,
   				ObjectProvider<PostRequestAuthenticationFailureHandler> authenticationFailureHandler,
				ObjectProvider<SessionAuthenticationStrategy> sessionAuthenticationStrategyProvider) {
			
			super(bizProperties, csrfTokenRepositoryProvider.getIfAvailable(), configurationSourceProvider.getIfAvailable());
   			
			this.bizProperties = bizProperties;
			this.authcProperties = faceIDProperties;
			
			this.authenticationManager = authenticationManagerProvider.getIfAvailable();
			this.rememberMeServices = rememberMeServicesProvider.getIfAvailable();
			
			this.authenticationProvider = faceIDAuthenticationProvider.getIfAvailable();
			this.authenticationSuccessHandler = authenticationSuccessHandler.getIfAvailable();
   			this.authenticationFailureHandler = authenticationFailureHandler.getIfAvailable();
			this.sessionAuthenticationStrategy = sessionAuthenticationStrategyProvider.getIfAvailable();
		}

		@Override
		public AuthenticationManager authenticationManagerBean() throws Exception {
   			AuthenticationManager parentManager = authenticationManager == null ? super.authenticationManagerBean() : authenticationManager;
			ProviderManager authenticationManager = new ProviderManager( Arrays.asList(authenticationProvider), parentManager);
			// 不擦除认证密码，擦除会导致TokenBasedRememberMeServices因为找不到Credentials再调用UserDetailsService而抛出UsernameNotFoundException
			authenticationManager.setEraseCredentialsAfterAuthentication(false);
			return authenticationManager;
		}
		
		public FaceIDAuthenticationProcessingFilter authenticationProcessingFilter() throws Exception {
	    	
			FaceIDAuthenticationProcessingFilter authenticationFilter = new FaceIDAuthenticationProcessingFilter();
			
			/**
			 * 批量设置参数
			 */
			PropertyMapper map = PropertyMapper.get().alwaysApplyingWhenNonNull();
			
			map.from(bizProperties.getSessionMgt().isAllowSessionCreation()).to(authenticationFilter::setAllowSessionCreation);
			
			map.from(authenticationManagerBean()).to(authenticationFilter::setAuthenticationManager);
			map.from(authenticationSuccessHandler).to(authenticationFilter::setAuthenticationSuccessHandler);
			map.from(authenticationFailureHandler).to(authenticationFilter::setAuthenticationFailureHandler);
			
			map.from(authcProperties.getAuthc().getLoginUrlPatterns()).to(authenticationFilter::setFilterProcessesUrl);
			map.from(authcProperties.getAuthc().isPostOnly()).to(authenticationFilter::setPostOnly);
			map.from(rememberMeServices).to(authenticationFilter::setRememberMeServices);
			map.from(sessionAuthenticationStrategy).to(authenticationFilter::setSessionAuthenticationStrategy);
			map.from(authcProperties.getAuthc().isContinueChainBeforeSuccessfulAuthentication()).to(authenticationFilter::setContinueChainBeforeSuccessfulAuthentication);
			
	        return authenticationFilter;
	    }
		
	    @Override
		public void configure(AuthenticationManagerBuilder auth) throws Exception {
	        auth.authenticationProvider(authenticationProvider);
	        super.configure(auth);
	    }
		
		@Override
		public void configure(HttpSecurity http) throws Exception {
			
			http.antMatcher(authcProperties.getAuthc().getPathPattern())
				.addFilterBefore(authenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class);
			
			super.configure(http);
		}
		
		@Override
	    public void configure(WebSecurity web) throws Exception {
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

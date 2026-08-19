package org.springframework.security.boot;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.biz.web.servlet.i18n.LocaleContextFilter;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.PropertyMapper;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.faceid.SecurityOpenIDAuthcProperties;
import org.springframework.security.boot.faceid.authentication.FaceIDAuthenticationProcessingFilter;
import org.springframework.security.boot.utils.WebSecurityUtils;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

/**
 * Web security filter configuration for face-ID authentication. <p>Registers the
 * {@link FaceIDAuthenticationProcessingFilter} and wires the security chain (entry point,
 * success/failure handlers, remember-me and session strategy) when the application is a web
 * application and face-ID authentication is enabled.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@Configuration
@AutoConfigureBefore(name = {
	"org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration"
})
/**
 * <p>Configuration properties.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@ConditionalOnWebApplication
@ConditionalOnProperty(prefix = SecurityFaceIDProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityFaceIDProperties.class, SecurityOpenIDAuthcProperties.class, SecurityBizProperties.class })
public class SecurityFaceIDFilterConfiguration {

	/**
	 * Inner {@code WebSecurityConfigurerAdapter} that builds the face-ID security filter chain.
	 */
	@Configuration
	@EnableConfigurationProperties({ SecurityFaceIDProperties.class, SecurityBizProperties.class })
	@Order(Ordered.HIGHEST_PRECEDENCE + 3)
	static class FaceIDWebSecurityConfigurerAdapter extends WebSecurityBizConfigurerAdapter {

	    private final SecurityOpenIDAuthcProperties authcProperties;

	    private final LocaleContextFilter localeContextFilter;
	    private final AuthenticationEntryPoint authenticationEntryPoint;
	    private final AuthenticationSuccessHandler authenticationSuccessHandler;
	    private final AuthenticationFailureHandler authenticationFailureHandler;
    	private final RememberMeServices rememberMeServices;
		private final SessionAuthenticationStrategy sessionAuthenticationStrategy;
	
		/**
		 * Constructs the face-ID web security configurer, resolving optional collaborators
		 * from the Spring context via {@link ObjectProvider}.
		 * @param bizProperties the common security business properties
		 * @param sessionMgtProperties the session-management properties
		 * @param authcProperties the face-ID authentication properties
		 * @param localeContextProvider the locale-context filter provider
		 * @param authenticationProvider the authentication-provider provider
		 * @param authenticationListenerProvider the authentication-listener provider
		 * @param authenticationEntryPointProvider the entry-point provider
		 * @param authenticationSuccessHandlerProvider the success-handler provider
		 * @param authenticationFailureHandlerProvider the failure-handler provider
		 * @param rememberMeServicesProvider the remember-me services provider
		 * @param sessionAuthenticationStrategyProvider the session-authentication-strategy provider
		 */
		public FaceIDWebSecurityConfigurerAdapter(

				SecurityBizProperties bizProperties,
				SecuritySessionMgtProperties sessionMgtProperties,
				SecurityOpenIDAuthcProperties authcProperties,

   				ObjectProvider<LocaleContextFilter> localeContextProvider,
				ObjectProvider<AuthenticationProvider> authenticationProvider,
   				ObjectProvider<AuthenticationListener> authenticationListenerProvider,
   				ObjectProvider<MatchedAuthenticationEntryPoint> authenticationEntryPointProvider,
   				ObjectProvider<MatchedAuthenticationSuccessHandler> authenticationSuccessHandlerProvider,
   				ObjectProvider<MatchedAuthenticationFailureHandler> authenticationFailureHandlerProvider,
   				ObjectProvider<RememberMeServices> rememberMeServicesProvider,

				ObjectProvider<SessionAuthenticationStrategy> sessionAuthenticationStrategyProvider) {
			
			super(bizProperties, sessionMgtProperties, authenticationProvider.stream().collect(Collectors.toList()));
   			
			this.authcProperties = authcProperties;
			
			this.localeContextFilter = localeContextProvider.getIfAvailable();
			List<AuthenticationListener> authenticationListeners = authenticationListenerProvider.stream().collect(Collectors.toList());
			this.authenticationEntryPoint = WebSecurityUtils.authenticationEntryPoint(authcProperties, sessionMgtProperties, authenticationEntryPointProvider.stream().collect(Collectors.toList()));
   			this.authenticationSuccessHandler = WebSecurityUtils.authenticationSuccessHandler(authcProperties, sessionMgtProperties, authenticationListeners, authenticationSuccessHandlerProvider.stream().collect(Collectors.toList()));
   			this.authenticationFailureHandler = WebSecurityUtils.authenticationFailureHandler(authcProperties, sessionMgtProperties, authenticationListeners, authenticationFailureHandlerProvider.stream().collect(Collectors.toList()));
   			this.rememberMeServices = rememberMeServicesProvider.getIfAvailable();
   			this.sessionAuthenticationStrategy = sessionAuthenticationStrategyProvider.getIfAvailable();
			
		}

		
		/**
		 * Builds the face-ID authentication filter, mapping bound properties onto it.
		 * @return the configured {@link FaceIDAuthenticationProcessingFilter}
		 * @throws Exception if the authentication manager cannot be resolved
		 */
		public FaceIDAuthenticationProcessingFilter authenticationProcessingFilter() throws Exception {
	    	
			FaceIDAuthenticationProcessingFilter authenticationFilter = new FaceIDAuthenticationProcessingFilter();
			
			/**
			 * 批量设置参数
			 */
			PropertyMapper map = PropertyMapper.get();
			
			map.from(getSessionMgtProperties().isAllowSessionCreation()).to(authenticationFilter::setAllowSessionCreation);
			
			map.from(authenticationManagerBean()).to(authenticationFilter::setAuthenticationManager);
			map.from(authenticationSuccessHandler).to(authenticationFilter::setAuthenticationSuccessHandler);
			map.from(authenticationFailureHandler).to(authenticationFilter::setAuthenticationFailureHandler);
			
			map.from(authcProperties.getLoginUrl()).to(authenticationFilter::setFilterProcessesUrl);
			map.from(authcProperties.isPostOnly()).to(authenticationFilter::setPostOnly);
			map.from(rememberMeServices).to(authenticationFilter::setRememberMeServices);
			map.from(sessionAuthenticationStrategy).to(authenticationFilter::setSessionAuthenticationStrategy);
			map.from(authcProperties.isContinueChainBeforeSuccessfulAuthentication()).to(authenticationFilter::setContinueChainBeforeSuccessfulAuthentication);
			
	        return authenticationFilter;
	    }
		
		/**
		 * Configures the {@link HttpSecurity} for the face-ID login flow.
		 * @param http the security builder
		 * @throws Exception if a configuration error occurs
		 */
		@Override
		public void configure(HttpSecurity http) throws Exception {
			
			http.securityMatcher(authcProperties.getPathPattern())
				.exceptionHandling(config -> config.authenticationEntryPoint(authenticationEntryPoint))
				.httpBasic(config -> config.disable())
				.addFilterBefore(localeContextFilter, UsernamePasswordAuthenticationFilter.class)
				.addFilterBefore(authenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class);
			
			super.configure(http, authcProperties.getCors());
   	    	super.configure(http, authcProperties.getCsrf());
   	    	super.configure(http, authcProperties.getHeaders());
	    	super.configure(http);
	    	
		}
		
		/**
		 * Configures the {@link WebSecurity} (e.g. ignored request paths).
		 * @param web the web security builder
		 * @throws Exception if a configuration error occurs
		 */
		@Override
	    public void configure(WebSecurity web) throws Exception {
	    	super.configure(web);
	    }
		
	}
	
}

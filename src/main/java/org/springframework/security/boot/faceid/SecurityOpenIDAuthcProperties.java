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
package org.springframework.security.boot.faceid;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.security.boot.biz.authentication.AuthenticatingFailureCounter;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationProcessingFilter;
import org.springframework.security.boot.biz.property.SecurityAuthcProperties;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

/**
 * Security authentication properties for the face-ID (OpenID-style) login flow. <p>Binds the
 * {@code spring.security.jwt.authc} properties used to configure login, redirect, success,
 * unauthorized and failure URLs as well as OpenID identifier matching.</p>
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@ConfigurationProperties(SecurityOpenIDAuthcProperties.PREFIX)
@Getter
@Setter
@ToString
public class SecurityOpenIDAuthcProperties extends SecurityAuthcProperties {

	public static final String PREFIX = "spring.security.jwt.authc";
	public static final String DEFAULT_CLAIMED_IDENTITY_FIELD = "openid_identifier";

	/** Authorization path pattern. */
	private String pathPattern = "/**";

	/** Login URL: the address visited when no session exists. */
	private String loginUrl = "/authz/login";
	private String loginUrlPatterns = "/login";
	/** Redirect URL: the address to redirect to after the session is invalidated. */
	private String redirectUrl = "/";
	/** Home page: the path to redirect to after a successful login. */
	private String successUrl = "/index";;
	/** Unauthorized page: the path to redirect to when access is denied. */
	private String unauthorizedUrl = "/error";
	/** Failure page: the path to redirect to when authentication fails. */
	private String failureUrl = "/error";

	/** the regular expression for matching on OpenID's (i.e."https://www.google.com/.*", ".*yahoo.com.*", etc) */
	private String identifierPattern = "";
	
	/** The URL that determines if authentication is required */
	private String filterProcessesUrl;

	private boolean allowSessionCreation = true;
	/**
	 * The name of the request parameter containing the OpenID identity, as
	 * submitted from the initial login form. Defaults to "openid_identifier"
	 */
	private String claimedIdentityFieldName = DEFAULT_CLAIMED_IDENTITY_FIELD;

	/**
	 * Maps the <tt>return_to url</tt> to a realm, for example:
	 *
	 * <pre>
	 * http://www.example.com/login/openid -&gt; http://www.example.com/realm
	 * </pre>
	 *
	 * If no mapping is provided then the returnToUrl will be parsed to extract the
	 * protocol, hostname and port followed by a trailing slash. This means that
	 * <tt>http://www.example.com/login/openid</tt> will automatically become
	 * <tt>http://www.example.com:80/</tt>
	 */
	private Map<String, String> realmMapping = Collections.emptyMap();

	/**
	 * Specifies any extra parameters submitted along with the identity field which
	 * should be appended to the return_to URL which is assembled by
	 * buildReturnToUrl.
	 * <p>
	 * If not set, it will default to the parameter name used by the
	 * RememberMeServices obtained from the parent class (if one is set).
	 */
	private Set<String> returnToUrlParameters = Collections.emptySet();

	
	
	/** the username parameter name. Defaults to "username". */
	private String usernameParameter = UsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_USERNAME_KEY;
	/** the password parameter name. Defaults to "password". */
	private String passwordParameter = UsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_PASSWORD_KEY;
	/**
	 * Indicates if the filter chain should be continued prior to delegation to
	 * {@link #successfulAuthentication(HttpServletRequest, HttpServletResponse, FilterChain, Authentication)}
	 * , which may be useful in certain environment (such as Tapestry applications).
	 * Defaults to <code>false</code>.
	 */
	private boolean continueChainBeforeSuccessfulAuthentication = false;
	private boolean postOnly = true;
	private String retryTimesKeyParameter = AuthenticatingFailureCounter.DEFAULT_RETRY_TIMES_KEY_PARAM_NAME;
	private String retryTimesKeyAttribute = PostRequestAuthenticationProcessingFilter.DEFAULT_RETRY_TIMES_KEY_ATTRIBUTE_NAME;
	/** Maximum number of retry to login . */
	private int retryTimesWhenAccessDenied = 3;
	private boolean useForward = false;

	/**
	 * Returns the login URL: the address visited when no session exists.
	 * @return the login URL
	 */
	public String getLoginUrl() {
		return loginUrl;
	}

	/**
	 * Sets the login URL.
	 * @param loginUrl the login URL to set
	 */
	public void setLoginUrl(String loginUrl) {
		this.loginUrl = loginUrl;
	}

}

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
package org.springframework.security.boot.faceid.authentication;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Part;

import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.boot.biz.SpringSecurityBizMessageSource;
import org.springframework.security.boot.biz.authentication.PostOnlyAuthenticationProcessingFilter;
import org.springframework.security.boot.faceid.exception.AuthenticationFaceNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

public class FaceIDAuthenticationProcessingFilter extends PostOnlyAuthenticationProcessingFilter {

	protected MessageSourceAccessor messages = SpringSecurityBizMessageSource.getAccessor();
	public static final String SPRING_SECURITY_FORM_FACE_KEY = "face";

    private String faceParameter = SPRING_SECURITY_FORM_FACE_KEY;
    private boolean postOnly = true;
	
    public FaceIDAuthenticationProcessingFilter() {
    	super(new AntPathRequestMatcher("/faceid", "POST"));
    }
    
    @Override
    public Authentication doAttemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {
 
		Part face = request.getPart(getFaceParameter());
		
	 	// 没有提供人脸数据
		if(face == null) {
			logger.debug("No face image found in request.");
			throw new AuthenticationFaceNotFoundException("No face image found in request.");
		}
		
		AbstractAuthenticationToken authRequest = new FaceIDAuthenticationToken(face.getInputStream());

		// Allow subclasses to set the "details" property
		setDetails(request, authRequest);

		return this.getAuthenticationManager().authenticate(authRequest);

    }

    /**
	 * Provided so that subclasses may configure what is put into the authentication
	 * request's details property.
	 *
	 * @param request that an authentication request is being created for
	 * @param authRequest the authentication request object that should have its details
	 * set
	 */
	protected void setDetails(HttpServletRequest request,
			AbstractAuthenticationToken authRequest) {
		authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
	}
	
	public String getFaceParameter() {
		return faceParameter;
	}

	public void setFaceParameter(String faceParameter) {
		this.faceParameter = faceParameter;
	}

	public boolean isPostOnly() {
		return postOnly;
	}

	public void setPostOnly(boolean postOnly) {
		this.postOnly = postOnly;
	}

}
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

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.Part;

import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.boot.biz.SpringSecurityBizMessageSource;
import org.springframework.security.boot.biz.authentication.PostOnlyAuthenticationProcessingFilter;
import org.springframework.security.boot.faceid.exception.AuthenticationFaceNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

/**
 * Processes a face-ID authentication request submitted as a multipart form. <p>Extracts the
 * uploaded face image part and creates an unauthenticated {@link FaceIDAuthenticationToken}
 * that is passed to the {@code AuthenticationManager} for verification.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class FaceIDAuthenticationProcessingFilter extends PostOnlyAuthenticationProcessingFilter {

	protected MessageSourceAccessor messages = SpringSecurityBizMessageSource.getAccessor();
	/** Default name of the form part that carries the face image: "face". */
	public static final String SPRING_SECURITY_FORM_FACE_KEY = "face";

    private String faceParameter = SPRING_SECURITY_FORM_FACE_KEY;
    private boolean postOnly = true;

    /**
     * Constructs a filter that intercepts POST requests to {@code /faceid}.
     */
    public FaceIDAuthenticationProcessingFilter() {
		super(PathPatternRequestMatcher.pathPattern(HttpMethod.POST, "/faceid"));
    }

    /**
     * Attempts to authenticate by reading the face image part from the request.
     * @param request the HTTP request carrying the face image
     * @param response the HTTP response
     * @return the authenticated token produced by the authentication manager
     * @throws AuthenticationException if no face image is found in the request or authentication fails
     * @throws IOException if the face image part cannot be read
     * @throws ServletException if the request part cannot be resolved
     */
    @Override
    public Authentication doAttemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {

		Part face = request.getPart(getFaceParameter());

		// No face image data provided
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

	/**
	 * Returns the name of the request part that carries the face image.
	 * @return the face parameter name
	 */
	public String getFaceParameter() {
		return faceParameter;
	}

	/**
	 * Sets the name of the request part that carries the face image.
	 * @param faceParameter the face parameter name
	 */
	public void setFaceParameter(String faceParameter) {
		this.faceParameter = faceParameter;
	}

	/**
	 * Returns whether only POST requests are accepted.
	 * @return {@code true} if only POST is accepted
	 */
	public boolean isPostOnly() {
		return postOnly;
	}

	/**
	 * Sets whether only POST requests are accepted.
	 * @param postOnly {@code true} to accept only POST requests
	 */
	public void setPostOnly(boolean postOnly) {
		this.postOnly = postOnly;
	}

}

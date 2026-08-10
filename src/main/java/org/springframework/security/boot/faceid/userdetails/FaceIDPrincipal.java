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
package org.springframework.security.boot.faceid.userdetails;

import java.util.Collection;

import org.springframework.security.boot.biz.userdetails.SecurityPrincipal;
import org.springframework.security.core.GrantedAuthority;

/**
 * Authenticated principal carrying face-recognition data. <p>Extends {@link SecurityPrincipal}
 * with the face image and identifiers resolved during face-ID authentication.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@SuppressWarnings("serial")
public class FaceIDPrincipal extends SecurityPrincipal {

	/**
	 * Identifier of the face recognition record.
	 */
	protected String faceId;
	/**
	 * Base64-encoded face image data (without the data-URI prefix, e.g. without
	 * {@code data:image/jpg;base64,}).
	 */
	protected String face;
	/**
	 * Face image type. One of:
	 * <ul>
	 *   <li>{@code LIVE}: live photo (phone/camera shot or internet image);</li>
	 *   <li>{@code IDCARD}: identity-card chip photo;</li>
	 *   <li>{@code WATERMARK}: watermarked document photo;</li>
	 *   <li>{@code CERT}: document photo (ID card, badge, passport, student card, etc.).</li>
	 * </ul>
	 * Defaults to {@code LIVE}.
	 */
	protected String faceType;
	/**
	 * Unique token of the face image.
	 */
	protected String faceToken;

	/**
	 * Constructs a principal with the given username, password and role names.
	 * @param username the username
	 * @param password the password
	 * @param roles the role names
	 */
	public FaceIDPrincipal(String username, String password, String... roles) {
		super(username, password, roles);
	}

	/**
	 * Constructs a principal with the given username, password and granted authorities.
	 * @param username the username
	 * @param password the password
	 * @param authorities the granted authorities
	 */
	public FaceIDPrincipal(String username, String password, Collection<? extends GrantedAuthority> authorities) {
		super(username, password, authorities);
	}

	/**
	 * Constructs a principal with full account-status flags.
	 * @param username the username
	 * @param password the password
	 * @param enabled whether the account is enabled
	 * @param accountNonExpired whether the account is non-expired
	 * @param credentialsNonExpired whether the credentials are non-expired
	 * @param accountNonLocked whether the account is non-locked
	 * @param authorities the granted authorities
	 */
	public FaceIDPrincipal(String username, String password, boolean enabled, boolean accountNonExpired,
			boolean credentialsNonExpired, boolean accountNonLocked,
			Collection<? extends GrantedAuthority> authorities) {
		super(username, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
	}

	/**
	 * Returns the face-recognition record identifier.
	 * @return the face record id
	 */
	public String getFaceId() {
		return faceId;
	}

	/**
	 * Sets the face-recognition record identifier.
	 * @param faceId the face record id
	 */
	public void setFaceId(String faceId) {
		this.faceId = faceId;
	}

	/**
	 * Returns the base64-encoded face image.
	 * @return the face image data
	 */
	public String getFace() {
		return face;
	}

	/**
	 * Sets the base64-encoded face image.
	 * @param face the face image data
	 */
	public void setFace(String face) {
		this.face = face;
	}

	/**
	 * Returns the face image type.
	 * @return the face image type
	 */
	public String getFaceType() {
		return faceType;
	}

	/**
	 * Sets the face image type.
	 * @param faceType the face image type
	 */
	public void setFaceType(String faceType) {
		this.faceType = faceType;
	}

	/**
	 * Returns the unique face image token.
	 * @return the face token
	 */
	public String getFaceToken() {
		return faceToken;
	}

	/**
	 * Sets the unique face image token.
	 * @param faceToken the face token
	 */
	public void setFaceToken(String faceToken) {
		this.faceToken = faceToken;
	}

}

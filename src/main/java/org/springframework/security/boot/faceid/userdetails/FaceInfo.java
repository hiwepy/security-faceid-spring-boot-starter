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

import lombok.Data;

/**
 * Face recognition data. <p>Carries the face image and metadata produced or consumed by a
 * {@code FaceRecognitionProvider} when authenticating a user via face recognition.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@Data
public class FaceInfo {

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
	 * Returns the face id.
	 *
	 * @return the face id
	 */
	public String getFaceId() { return faceId; }
	/**
	 * Sets the face id.
	 *
	 * @param faceId the face id
	 */
	public void setFaceId(String faceId) { this.faceId = faceId; }
	/**
	 * Returns the face.
	 *
	 * @return the face
	 */
	public String getFace() { return face; }
	/**
	 * Sets the face.
	 *
	 * @param face the face
	 */
	public void setFace(String face) { this.face = face; }
	/**
	 * Returns the face type.
	 *
	 * @return the face type
	 */
	public String getFaceType() { return faceType; }
	/**
	 * Sets the face type.
	 *
	 * @param faceType the face type
	 */
	public void setFaceType(String faceType) { this.faceType = faceType; }
	/**
	 * Returns the face token.
	 *
	 * @return the face token
	 */
	public String getFaceToken() { return faceToken; }
	/**
	 * Sets the face token.
	 *
	 * @param faceToken the face token
	 */
	public void setFaceToken(String faceToken) { this.faceToken = faceToken; }

	/**
	 * Determines whether equals.
	 *
	 * @param o the o
	 * @return the result
	 */
	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		FaceInfo faceInfo = (FaceInfo) o;
		return java.util.Objects.equals(faceId, faceInfo.faceId)
				&& java.util.Objects.equals(face, faceInfo.face)
				&& java.util.Objects.equals(faceType, faceInfo.faceType)
				&& java.util.Objects.equals(faceToken, faceInfo.faceToken);
	}

	/**
	 * hash Code.
	 *
	 * @return the result
	 */
	@Override
	public int hashCode() {
		return java.util.Objects.hash(faceId, face, faceType, faceToken);
	}

	/**
	 * to String.
	 *
	 * @return the result
	 */
	@Override
	public String toString() {
		return "FaceInfo{faceId='" + faceId + "', face='" + face + "', faceType='" + faceType + "', faceToken='" + faceToken + "'}";
	}

}

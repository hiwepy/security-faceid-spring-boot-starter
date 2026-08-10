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

/**
 * Type of a face image. <p>Enumerates the supported categories of face images used
 * during face recognition, ranging from everyday photos to identity-document photos.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public enum FaceType {

	/**
	 * Live photo: a portrait taken with a phone or camera, or obtained from the internet.
	 */
	LIVE,
	/**
	 * Identity-card chip photo: the portrait embedded in the chip of a second-generation
	 * identity card.
	 */
	IDCARD,
	/**
	 * Watermarked ID photo: usually a small watermarked image, e.g. a small image from a
	 * public-security network.
	 */
	WATERMARK,
	/**
	 * Document photo: a photo of a document such as an identity card, employee badge,
	 * passport or student card.
	 */
	CERT;

}

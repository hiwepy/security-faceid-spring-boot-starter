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

import org.springframework.security.boot.faceid.userdetails.FaceInfo;
import org.springframework.security.core.Authentication;

/**
 * Strategy for resolving face information from an authentication request. <p>Implementations
 * call an external face-recognition service to look up the {@link FaceInfo} that matches the
 * face image supplied in the authentication object.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */

public interface FaceRecognitionProvider {

	/**
	 * Loads the face information associated with the given authentication request.
	 * @param authentication the authentication request carrying the face image
	 * @return the resolved face information, or {@code null} if no matching face is found
	 */
	FaceInfo loadFaceInfo(Authentication authentication);

}

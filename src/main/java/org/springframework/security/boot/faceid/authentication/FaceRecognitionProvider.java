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
 * TODO
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */

public interface FaceRecognitionProvider {

	FaceInfo loadFaceInfo(Authentication authentication);
	
}

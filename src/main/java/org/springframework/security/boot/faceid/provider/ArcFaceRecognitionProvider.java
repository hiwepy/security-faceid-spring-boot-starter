/*
 * Copyright (c) 2018, vindell (https://github.com/vindell).
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
package org.springframework.security.boot.faceid.provider;

import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;

import com.alibaba.fastjson.JSONObject;
import com.arcsoft.face.spring.boot.ArcFaceRecognitionTemplate;
import com.arcsoft.face.spring.boot.FaceLiveness;
import com.knowway.cloud.api.exception.BizRuntimeException;
import com.knowway.cloud.authz.face.dao.IAuthzFaceDao;
import com.knowway.cloud.authz.face.dao.IAuthzFaceRepositoryDao;
import com.knowway.cloud.authz.face.dao.entities.AuthzFaceModel;

@Component
public class ArcFaceRecognitionProvider implements FaceRecognitionProvider {

	@Autowired
	private ArcFaceRecognitionTemplate faceRecognitionTemplate;
	@Autowired
	private IAuthzFaceDao authzFace;
	@Autowired
	private IAuthzFaceRepositoryDao authzFaceRepository;
	
	@Override
	public String getName() {
		return "arcface";
	}

	@Override
	public JSONObject detect(byte[] imageBytes, String filename) throws Exception {
		return getFaceRecognitionTemplate().detect(imageBytes);
	}

	@Override
	public JSONObject match(String userId, MultipartFile image) throws Exception {
		AuthzFaceModel model = getAuthzFace().getModel(userId);
		return getFaceRecognitionTemplate().match(image.getBytes(), Base64.getDecoder().decode(model.getFace()),  FaceLiveness.NONE);
	}

	
	public ArcFaceRecognitionTemplate getFaceRecognitionTemplate() {
		return faceRecognitionTemplate;
	}

	public IAuthzFaceDao getAuthzFace() {
		return authzFace;
	}

	public IAuthzFaceRepositoryDao getAuthzFaceRepository() {
		return authzFaceRepository;
	}

}

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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;

import com.alibaba.fastjson.JSONObject;
import com.baidu.ai.aip.spring.boot.FaceOption;
import com.baidu.ai.aip.spring.boot.FaceRecognitionV3Template;
import com.baidu.aip.util.Base64Util;
import com.knowway.cloud.authz.face.dao.IAuthzFaceDao;
import com.knowway.cloud.authz.face.dao.IAuthzFaceRepositoryDao;
import com.knowway.cloud.authz.face.dao.entities.AuthzFaceModel;
import com.knowway.cloud.authz.face.setup.FaceRecognitionProperties;

@Component
public class BaiduFaceRecognitionProvider implements FaceRecognitionProvider {

	@Autowired
	private FaceRecognitionV3Template faceRecognitionTemplate;
	@Autowired
	private FaceRecognitionProperties faceRecognitionProperties;
	@Autowired
	private IAuthzFaceDao authzFace;
	@Autowired
	private IAuthzFaceRepositoryDao authzFaceRepository;
	
	@Override
	public String getName() {
		return "baidu";
	}

	@Override
	public JSONObject detect(byte[] imageBytes, String filename) throws Exception {
		return getFaceRecognitionTemplate().detect(imageBytes);
	}

	@Override
	public JSONObject verify(MultipartFile image) throws Exception {
		// 对文件进行转码
		String imageBase64 = Base64Util.encode(image.getBytes());
		return getFaceRecognitionTemplate().faceVerify(imageBase64, FaceOption.COMMON);
	}

	@Override
	public JSONObject match(String userId, MultipartFile image) throws Exception {
		AuthzFaceModel model = getAuthzFace().getModel(userId);
		String imageBase64_2 = Base64Util.encode(image.getBytes());
		return getFaceRecognitionTemplate().match(model.getFace(), imageBase64_2);
	}

	@Override
	public JSONObject search(MultipartFile image) throws Exception {
		// 对文件进行转码
		String imageBase64 = Base64Util.encode(image.getBytes());
		return getFaceRecognitionTemplate().search(imageBase64, faceRecognitionProperties.getGroup());
	}

	@Override
	public JSONObject merge(MultipartFile template, MultipartFile target) throws Exception {
		return getFaceRecognitionTemplate().merge(template.getBytes(), target.getBytes());
	}
	
	public FaceRecognitionV3Template getFaceRecognitionTemplate() {
		return faceRecognitionTemplate;
	}

	public IAuthzFaceDao getAuthzFace() {
		return authzFace;
	}

	public IAuthzFaceRepositoryDao getAuthzFaceRepository() {
		return authzFaceRepository;
	}

}

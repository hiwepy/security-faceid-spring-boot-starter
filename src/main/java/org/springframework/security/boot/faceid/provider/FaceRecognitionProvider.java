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

import org.springframework.web.multipart.MultipartFile;

import com.alibaba.fastjson.JSONObject;

public interface FaceRecognitionProvider {

	/**
	 * Provider Name
	 * @return
	 */
	String getName();
	
	/**
	 * 人脸检测与属性分析：
	 * 1、人脸检测：检测图片中的人脸并标记出位置信息;
	 * 2、人脸关键点：展示人脸的核心关键点信息，及150个关键点信息。
	 * 3、人脸属性值：展示人脸属性信息，如年龄、性别等。
	 * 4、人脸质量信息：返回人脸各部分的遮挡、光照、模糊、完整度、置信度等信息。
	 * @param imageBytes 人脸图片文件
	 * @return
	 */
	JSONObject detect(byte[] imageBytes, String filename) throws Exception;

	/**
	 * 人脸对比：
	 * 1、两张人脸图片相似度对比：比对两张图片中人脸的相似度，并返回相似度分值；
	 * 2、 多种图片类型：支持生活照、证件照、身份证芯片照、带网纹照四种类型的人脸对比；
	 * 3、活体检测控制：基于图片中的破绽分析，判断其中的人脸是否为二次翻拍（举例：如用户A用手机拍摄了一张包含人脸的图片一，用户B翻拍了图片一得到了图片二，并用图片二伪造成用户A去进行识别操作，这种情况普遍发生在金融开户、实名认证等环节。）；
	 * 4、质量检测控制：分析图片的中人脸的模糊度、角度、光照强度等特征，判断图片质量；
	 * @param userId 用户ID
	 * @param image 人脸图片文件
	 * @return
	 */
	JSONObject match(String userId, MultipartFile image) throws Exception;
	
	
}

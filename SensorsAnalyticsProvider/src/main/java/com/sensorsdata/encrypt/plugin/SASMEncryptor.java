/*
 * Created by chenru on 2021/03/22.
 * Copyright 2015－2021 Sensors Data Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.sensorsdata.encrypt.plugin;

import com.sensorsdata.analytics.android.sdk.SALog;
import com.sensorsdata.analytics.android.sdk.encrypt.SAEncryptListener;
import com.sensorsdata.encrypt.SymmetricEncryptMode;
import com.sensorsdata.encrypt.utils.SAEncryptUtils;

import java.security.NoSuchAlgorithmException;

/**
 * SM2+SM4 加密
 */
public class SASMEncryptor implements SAEncryptListener {
    /**
     * 对称密钥
     */
    byte[] sm4Key;

    /**
     * 加密后的对称密钥
     */
    String mEncryptKey;

    @Override
    public String symmetricEncryptType() {
        return "SM4";
    }

    @Override
    public String encryptEvent(byte[] event) {
        return SAEncryptUtils.symmetricEncrypt(sm4Key, event, SymmetricEncryptMode.SM4);
    }

    @Override
    public String asymmetricEncryptType() {
        return "SM2";
    }

    @Override
    public String encryptSymmetricKeyWithPublicKey(String publicKey) {
        if (mEncryptKey == null) {
            try {
                sm4Key = SAEncryptUtils.generateSymmetricKey(SymmetricEncryptMode.SM4);
                mEncryptKey = SAEncryptUtils.sm2Encrypt(publicKey, sm4Key);
            } catch (NoSuchAlgorithmException e) {
                SALog.printStackTrace(e);
                return null;
            }
        }
        return mEncryptKey;
    }
}

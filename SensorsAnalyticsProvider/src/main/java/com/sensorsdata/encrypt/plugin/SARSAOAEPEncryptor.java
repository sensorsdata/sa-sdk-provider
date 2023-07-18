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
import com.sensorsdata.analytics.android.sdk.encrypt.AESSecretManager;
import com.sensorsdata.analytics.android.sdk.encrypt.impl.AbsSAEncrypt;
import com.sensorsdata.encrypt.ASymmetricEncryptMode;
import com.sensorsdata.encrypt.SymmetricEncryptMode;
import com.sensorsdata.encrypt.utils.SAEncryptUtils;

import java.security.NoSuchAlgorithmException;

/**
 * RSA + AES 加密
 */
public class SARSAOAEPEncryptor extends AbsSAEncrypt {
    /**
     * 对称密钥
     */
    byte[] aesKey;

    /**
     * 加密后的对称密钥
     */
    String mEncryptKey;

    @Override
    public String symmetricEncryptType() {
        return "AES";
    }

    @Override
    public String encryptEvent(byte[] event) {
        return SAEncryptUtils.symmetricEncrypt(aesKey, event, SymmetricEncryptMode.AES);
    }

    @Override
    public String asymmetricEncryptType() {
        return "RSA/ECB/OAEPPadding";
    }

    @Override
    public String encryptSymmetricKeyWithPublicKey(String publicKey) {
        if (mEncryptKey == null) {
            try {
                aesKey = SAEncryptUtils.generateSymmetricKey(SymmetricEncryptMode.AES);
                mEncryptKey = SAEncryptUtils.rsaEncryptAESKey(publicKey, aesKey, ASymmetricEncryptMode.RSA_OAEP);
            } catch (NoSuchAlgorithmException e) {
                SALog.printStackTrace(e);
                return null;
            }
        }
        return mEncryptKey;
    }

    @Override
    public String encryptEventRecord(String eventJson) {
        return AESSecretManager.getInstance().encryptAES(eventJson);
    }

    @Override
    public String decryptEventRecord(String encryptEvent) {
        return AESSecretManager.getInstance().decryptAES(encryptEvent);
    }
}

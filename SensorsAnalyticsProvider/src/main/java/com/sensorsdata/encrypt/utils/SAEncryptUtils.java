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

package com.sensorsdata.encrypt.utils;

import android.text.TextUtils;

import com.sensorsdata.analytics.android.sdk.SALog;
import com.sensorsdata.analytics.android.sdk.util.Base64Coder;
import com.sensorsdata.encrypt.ASymmetricEncryptMode;
import com.sensorsdata.encrypt.SymmetricEncryptMode;
import com.sensorsdata.encrypt.engine.SM2Engine;

import org.spongycastle.asn1.gm.GMNamedCurves;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.crypto.params.ECDomainParameters;
import org.spongycastle.crypto.params.ECPublicKeyParameters;
import org.spongycastle.crypto.params.ParametersWithRandom;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.util.encoders.Base64;
import org.spongycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import static javax.crypto.Cipher.ENCRYPT_MODE;

/**
 * 加密工具类
 */
public class SAEncryptUtils {
    private static final String TAG = "SA.EncryptProvider";

    /**
     * 随机生成 AES/SM4 加密秘钥
     *
     * @return AES/SM4 密钥
     */
    public static byte[] generateSymmetricKey(SymmetricEncryptMode mode) throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance(mode.algorithm);
        keyGen.init(128);
        SecretKey aesKey = keyGen.generateKey();
        return aesKey.getEncoded();
    }

    /**
     * @param publicKey sm2 公钥
     * @param cipher gzip 后的事件信息
     * @return encode 后的密文
     */
    public static String sm2Encrypt(String publicKey, byte[] cipher) {
        if (TextUtils.isEmpty(publicKey)) {
            return null;
        }
        try {
            X9ECParameters sm2ECParameters = GMNamedCurves.getByName("sm2p256v1");
            // 构造ECC算法参数，曲线方程、椭圆曲线G点、大整数N
            ECDomainParameters domainParameters =
                    new ECDomainParameters(sm2ECParameters.getCurve(), sm2ECParameters.getG(), sm2ECParameters.getN());
            //提取公钥点
            ECPoint pukPoint = sm2ECParameters.getCurve().decodePoint(Hex.decode(publicKey));
            ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(pukPoint, domainParameters);
            // 使用 C1C3C2 排列
            SM2Engine sm2Engine = new SM2Engine(SM2Engine.Mode.C1C3C2);
            // 设置sm2为加密模式
            sm2Engine.init(true, new ParametersWithRandom(publicKeyParameters, new SecureRandom()));
            byte[] arrayOfBytes;
            arrayOfBytes = sm2Engine.processBlock(cipher, 0, cipher.length);
            return new String(Base64.encode(arrayOfBytes));
        } catch (Exception e) {
            SALog.printStackTrace(e);
        }
        return null;
    }

    /**
     * 使用 AES/SM4 密钥对埋点数据加密
     *
     * @param key AES/SM4 加密秘钥
     * @param contentBytes gzip 后的加密内容
     * @param mode {@link SymmetricEncryptMode} 同步加密类型
     * @return AES/SM4 加密后的数据
     */
    public static String symmetricEncrypt(byte[] key, byte[] contentBytes, SymmetricEncryptMode mode) {
        if (key == null || contentBytes == null) {
            return null;
        }
        try {
            SecureRandom random = new SecureRandom();
            // 随机生成初始化向量
            byte[] ivBytes = new byte[16];
            random.nextBytes(ivBytes);
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, mode.algorithm);
            Cipher cipher = Cipher.getInstance(mode.transformation);
            cipher.init(ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(ivBytes));

            byte[] encryptedBytes = cipher.doFinal(contentBytes);
            ByteBuffer byteBuffer = ByteBuffer.allocate(ivBytes.length + encryptedBytes.length);
            byteBuffer.put(ivBytes);
            byteBuffer.put(encryptedBytes);
            byte[] cipherMessage = byteBuffer.array();
            return new String(Base64.encode(cipherMessage));
        } catch (Exception ex) {
            SALog.printStackTrace(ex);
        }
        return null;
    }

    /**
     * 使用 RSA 公钥对 AES 密钥加密
     *
     * @param publicKey，公钥秘钥
     * @param content，加密内容
     * @return 加密后的数据
     */
    public static String rsaEncryptAESKey(String publicKey, byte[] content, ASymmetricEncryptMode mode) {
        if (TextUtils.isEmpty(publicKey)) {
            SALog.i(TAG, "PublicKey is null.");
            return null;
        }
        try {
            byte[] keyBytes = Base64Coder.decode(publicKey);
            KeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keyBytes);
            Cipher cipher;
            KeyFactory keyFactory = KeyFactory.getInstance(mode.algorithm);
            Key rsaPublicKey = keyFactory.generatePublic(x509EncodedKeySpec);
            cipher = Cipher.getInstance(mode.transformation);
            cipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey);

            int contentLen = content.length;
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            int offSet = 0;
            byte[] cache;
            /*
             * RSA 最大加密明文大小：1024 位公钥：117，2048 为公钥：245
             */
            int MAX_ENCRYPT_BLOCK = 245;
            while (contentLen - offSet > 0) {
                if (contentLen - offSet > MAX_ENCRYPT_BLOCK) {
                    cache = cipher.doFinal(content, offSet, MAX_ENCRYPT_BLOCK);
                } else {
                    cache = cipher.doFinal(content, offSet, contentLen - offSet);
                }
                outputStream.write(cache, 0, cache.length);
                offSet += MAX_ENCRYPT_BLOCK;
            }
            byte[] encryptedData = outputStream.toByteArray();
            outputStream.close();
            return new String(Base64Coder.encode(encryptedData));
        } catch (Exception ex) {
            SALog.printStackTrace(ex);
        }
        return null;
    }
}

/*
 * Created by chenru on 2021/07/27.
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

//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package com.sensorsdata.encrypt.engine;

import org.spongycastle.crypto.CipherParameters;
import org.spongycastle.crypto.Digest;
import org.spongycastle.crypto.InvalidCipherTextException;
import org.spongycastle.crypto.digests.SM3Digest;
import org.spongycastle.crypto.params.ECDomainParameters;
import org.spongycastle.crypto.params.ECKeyParameters;
import org.spongycastle.crypto.params.ECPrivateKeyParameters;
import org.spongycastle.crypto.params.ECPublicKeyParameters;
import org.spongycastle.crypto.params.ParametersWithRandom;
import org.spongycastle.math.ec.ECConstants;
import org.spongycastle.math.ec.ECFieldElement;
import org.spongycastle.math.ec.ECMultiplier;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.math.ec.FixedPointCombMultiplier;
import org.spongycastle.util.Arrays;
import org.spongycastle.util.BigIntegers;
import org.spongycastle.util.Memoable;
import org.spongycastle.util.Pack;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * SM2 加解密引擎
 * SDK 反射调用，勿删
 */
public class SM2Engine {
    private final Digest digest;
    private final Mode mode;

    private boolean forEncryption;
    private ECKeyParameters ecKey;
    private ECDomainParameters ecParams;
    private int curveLength;
    private SecureRandom random;

    public SM2Engine() {
        this(new SM3Digest());
    }

    public SM2Engine(Mode mode) {
        this(new SM3Digest(), mode);
    }

    public SM2Engine(Digest digest) {
        this(digest, Mode.C1C2C3);
    }

    public SM2Engine(Digest digest, Mode mode) {
        if (mode == null) {
            throw new IllegalArgumentException("mode value invalid");
        }
        this.digest = digest;
        this.mode = mode;
    }

    public void init(boolean forEncryption, CipherParameters param) {
        this.forEncryption = forEncryption;

        if (forEncryption) {
            ParametersWithRandom rParam = (ParametersWithRandom) param;

            ecKey = (ECKeyParameters) rParam.getParameters();
            ecParams = ecKey.getParameters();

            ECPoint s = ((ECPublicKeyParameters) ecKey).getQ().multiply(ecParams.getH());
            if (s.isInfinity()) {
                throw new IllegalArgumentException("invalid key: [h]Q at infinity");
            }

            random = rParam.getRandom();
        } else {
            ecKey = (ECKeyParameters) param;
            ecParams = ecKey.getParameters();
        }
        curveLength = (ecParams.getCurve().getFieldSize() + 7) / 8;
    }

    public byte[] processBlock(
            byte[] in,
            int inOff,
            int inLen)
            throws InvalidCipherTextException {
        if (forEncryption) {
            return encrypt(in, inOff, inLen);
        } else {
            return decrypt(in, inOff, inLen);
        }
    }

    public int getOutputSize(int inputLen) {
        return (1 + 2 * curveLength) + inputLen + digest.getDigestSize();
    }

    protected ECMultiplier createBasePointMultiplier() {
        return new FixedPointCombMultiplier();
    }

    private byte[] encrypt(byte[] in, int inOff, int inLen)
            throws InvalidCipherTextException {
        byte[] c2 = new byte[inLen];

        System.arraycopy(in, inOff, c2, 0, c2.length);

        ECMultiplier multiplier = createBasePointMultiplier();

        byte[] c1;
        ECPoint kPB;
        do {
            BigInteger k = nextK();

            ECPoint c1P = multiplier.multiply(ecParams.getG(), k).normalize();

            c1 = c1P.getEncoded(false);

            kPB = ((ECPublicKeyParameters) ecKey).getQ().multiply(k).normalize();

            kdf(digest, kPB, c2);
        }
        while (notEncrypted(c2, in, inOff));

        byte[] c3 = new byte[digest.getDigestSize()];

        addFieldElement(digest, kPB.getAffineXCoord());
        digest.update(in, inOff, inLen);
        addFieldElement(digest, kPB.getAffineYCoord());

        digest.doFinal(c3, 0);

        switch (mode) {
            case C1C3C2:
                return Arrays.concatenate(c1, c3, c2);
            default:
                return Arrays.concatenate(c1, c2, c3);
        }
    }

    private byte[] decrypt(byte[] in, int inOff, int inLen)
            throws InvalidCipherTextException {
        byte[] c1 = new byte[curveLength * 2 + 1];

        System.arraycopy(in, inOff, c1, 0, c1.length);

        ECPoint c1P = ecParams.getCurve().decodePoint(c1);

        ECPoint s = c1P.multiply(ecParams.getH());
        if (s.isInfinity()) {
            throw new InvalidCipherTextException("[h]C1 at infinity");
        }

        c1P = c1P.multiply(((ECPrivateKeyParameters) ecKey).getD()).normalize();

        int digestSize = this.digest.getDigestSize();
        byte[] c2 = new byte[inLen - c1.length - digestSize];

        if (mode == Mode.C1C3C2) {
            System.arraycopy(in, inOff + c1.length + digestSize, c2, 0, c2.length);
        } else {
            System.arraycopy(in, inOff + c1.length, c2, 0, c2.length);
        }

        kdf(digest, c1P, c2);

        byte[] c3 = new byte[digest.getDigestSize()];

        addFieldElement(digest, c1P.getAffineXCoord());
        digest.update(c2, 0, c2.length);
        addFieldElement(digest, c1P.getAffineYCoord());

        digest.doFinal(c3, 0);

        int check = 0;
        if (mode == Mode.C1C3C2) {
            for (int i = 0; i != c3.length; i++) {
                check |= c3[i] ^ in[inOff + c1.length + i];
            }
        } else {
            for (int i = 0; i != c3.length; i++) {
                check |= c3[i] ^ in[inOff + c1.length + c2.length + i];
            }
        }

        this.clearBlock(c1);
        this.clearBlock(c3);
        if (check != 0) {
            this.clearBlock(c2);
            throw new InvalidCipherTextException("invalid cipher text");
        } else {
            return c2;
        }
    }

    private boolean notEncrypted(byte[] encData, byte[] in, int inOff) {
        for (int i = 0; i != encData.length; i++) {
            if (encData[i] != in[inOff + i]) {
                return false;
            }
        }
        return true;
    }

    private void kdf(Digest digest, ECPoint c1, byte[] encData) {
        int digestSize = digest.getDigestSize();
        byte[] buf = new byte[Math.max(4, digestSize)];
        int off = 0;

        Memoable memo = null;
        Memoable copy = null;

        if (digest instanceof Memoable) {
            addFieldElement(digest, c1.getAffineXCoord());
            addFieldElement(digest, c1.getAffineYCoord());
            memo = (Memoable) digest;
            copy = memo.copy();
        }

        int ct = 0;

        while (off < encData.length) {
            if (memo != null) {
                memo.reset(copy);
            } else {
                addFieldElement(digest, c1.getAffineXCoord());
                addFieldElement(digest, c1.getAffineYCoord());
            }

            Pack.intToBigEndian(++ct, buf, 0);
            digest.update(buf, 0, 4);
            digest.doFinal(buf, 0);

            int xorLen = Math.min(digestSize, encData.length - off);
            xor(encData, buf, off, xorLen);
            off += xorLen;
        }
    }

    private void xor(byte[] data, byte[] kdfOut, int dOff, int dRemaining) {
        for (int i = 0; i != dRemaining; i++) {
            data[dOff + i] ^= kdfOut[i];
        }
    }

    private BigInteger nextK() {
        int qBitLength = this.ecParams.getN().bitLength();
        BigInteger k;
        do {
            do {
                k = new BigInteger(qBitLength, this.random);
            } while (k.equals(ECConstants.ZERO));
        } while (k.compareTo(this.ecParams.getN()) >= 0);
        return k;
    }

    private void addFieldElement(Digest digest, ECFieldElement v) {
        byte[] p = BigIntegers.asUnsignedByteArray(curveLength, v.toBigInteger());
        digest.update(p, 0, p.length);
    }

    private void clearBlock(byte[] block) {
        for (int i = 0; i != block.length; ++i) {
            block[i] = 0;
        }
    }

    public enum Mode {
        C1C2C3, C1C3C2
    }
}

// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

package example;

import java.security.SecureRandom;
import java.security.Key;
import javax.crypto.Cipher;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadKeyTemplates;
import com.google.crypto.tink.proto.KeyTemplate;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.apache.xml.security.encryption.XMLCipher;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

interface Processor {
    byte[] apply(byte[] data);
}

class FirstProcessor implements Processor {
    public byte[] apply(byte[] data) { return data; }
}

class SecondProcessor implements Processor {
    public byte[] apply(byte[] data) { return data; }
}

class Acceptance {
    JcePGPDataEncryptorBuilder builder(int alg) {
        return new JcePGPDataEncryptorBuilder(alg)
            .setSecureRandom(new SecureRandom())
            .setWithIntegrityPacket(true);
    }

    byte[] tink(byte[] data) throws Exception {
        KeyTemplate template = AeadKeyTemplates.AES128_GCM;
        KeysetHandle handle = KeysetHandle.generateNew(template);
        Aead aead = handle.getPrimitive(Aead.class);
        byte[] encrypted = aead.encrypt(data, data);
        return aead.decrypt(encrypted, data);
    }

    Document xml(Document document, Element element, Key key) throws Exception {
        XMLCipher cipher = XMLCipher.getInstance(XMLCipher.AES_256_GCM);
        cipher.init(XMLCipher.ENCRYPT_MODE, key);
        return cipher.doFinal(document, element);
    }

    byte[] run(byte[] data, byte[] key, String runtimeProvider) throws Exception {
        Cipher.getInstance("AES/GCM/NoPadding", "BC");
        Cipher.getInstance("AES/GCM/NoPadding", runtimeProvider);
        KeyParameter params = new KeyParameter(key);
        params.getKey();
        GCMBlockCipher gcm = new GCMBlockCipher();
        gcm.init(true, params);
        gcm.init(true, new KeyParameter(data));
        gcm.getOutputSize(16);
        AESEngine engine = new AESEngine();
        helper(data, key, 16);
        engine.processBlock(data, 0, data, 0);
        dispatch(null, data);
        return data;
    }

    byte[] helper(byte[] data, byte[] key, int size) {
        return leaf(data, key, size);
    }

    byte[] leaf(byte[] data, byte[] key, int size) {
        return data;
    }

    byte[] dispatch(Processor processor, byte[] data) {
        return processor.apply(data);
    }
}

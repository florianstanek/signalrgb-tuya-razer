import udp from "@SignalRGB/udp";
import BaseClass from './Libs/BaseClass.test.js';
import { MD5 } from './Crypto/MD5.test.js';
import { AES } from "./Crypto/AES.test.js";
import { Hex } from "./Crypto/Hex.test.js";
import { Utf8 } from "./Crypto/Utf8.test.js";
import { GCM } from "./Crypto/lib/algorithm/cipher/mode/GCM.test.js";
import { ECB } from "./Crypto/lib/algorithm/cipher/mode/ECB.test.js";
import { Word32Array } from "./Crypto/lib/Word32Array.test.js";
import { Base64 } from "./Crypto/lib/encoder/Base64.test.js";

export default class TuyaBroadcast extends BaseClass
{
    constructor()
    {
        super();
        this.ports = [6666, 6667];
        this.key = MD5.hash('yGAdlopoPVldABfn');
        this.sockets = [];
        this.init();
    }

    init()
    {
        for (const port of this.ports)
        {
            const socket = udp.createSocket();
            socket.bind(port);
            socket.on('message', this.handleBroadcast.bind(this));
            socket.on('error', service.log);
            this.sockets.push(socket);
        }
    }

    handleBroadcast(message)
    {
        const data = new Uint8Array(message.buffer);
        const prefix = data.slice(0, 4);
        let tuyaDeviceData = false;

        if (this.equals(prefix, new Uint8Array([0x00, 0x00, 0x55, 0xAA]))) // Protocol up to 3.3
        {
            tuyaDeviceData = this.decryptECB(data);
        } else if (this.equals(prefix, new Uint8Array([0x00, 0x00, 0x66, 0x99]))) // Protocol 3.4+
        {
            tuyaDeviceData = this.decryptGCM(data);
        } else
        {
            service.log('Unknown protocol');
        }

        if (tuyaDeviceData)
        {
            
            this.trigger('broadcast.device', tuyaDeviceData);
        }
    }

    decryptECB(data)
    {
        try {
            const payload = new Word32Array(data.slice(20, -8));
            const decrypted = AES.decrypt(payload.toString(Base64), this.key, {mode: ECB});
            const text = decrypted.toString(Utf8);
            const jsonStart = text.indexOf('{');
            const jsonEnd = text.lastIndexOf('}');
            if (jsonStart < 0 || jsonEnd < jsonStart) return false;
            return JSON.parse(text.slice(jsonStart, jsonEnd + 1));
        } catch(ex)
        {
            service.log('Failed to decode Tuya 3.3 discovery packet: ' + ex);
            return false;
        }
    }

    toHexString(byteArray)
    {
        const hex = Array.from(byteArray, function(byte) {
            return ('0' + (byte & 0xFF).toString(16)).slice(-2);
        }).join('');
        return hex;
    }

    decryptGCM(data)
    {
        const aad = Hex.parse(this.toHexString(data.slice(4, 18)));
        const iv = Hex.parse(this.toHexString(data.slice(18, 30)));

        const payload = Hex.parse(this.toHexString(data.slice(30, -20)));
        const tag = this.toHexString(data.slice(-20,-4));

        try {
            var authtag = GCM.mac(AES, this.key, iv, aad, payload);

            // Let's see if the data is correct
            if (authtag.toString() !== tag.toString())
            {
                return false;
            }

            const decrypted = AES.decrypt(payload.toString(Base64), this.key, {iv: iv, mode: GCM});
            const byteArray = decrypted.toUint8Array();
            const jsonByteArray = new Word32Array(byteArray.slice(4));
            const JSONString = jsonByteArray.toString(Utf8);

            try {
                const jsonObject = JSON.parse(JSONString.trim());
                // service.log(jsonObject);
                return jsonObject;
            } catch(ex)
            {
                service.log('Error parsing string');
                service.log(ex);
            }
        } catch(ex)
        {
            service.log(ex);
        }

        return false;
    }
}

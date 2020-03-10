const SPID = "FEF23C7E73A379823CE71FF289CFBC07";
const SIGRL = 0;
const SIZE_SIGRL = 0;
const AES_CMAC_KDF_ID = 0x0001;
const SAMPLE_QUOTE_LINKABLE_SIGNATURE = 1;
const {
    switchEndian,
    toHex,
    hexStringToArray,
    buf2hexString,
    hexString2Buffer,
} = require("./utils");
const {
    signPriKey,
} = require("./config")

const crypto = require("crypto")
const aesCmac = require("node-aes-cmac").aesCmac;
const EC = require('elliptic').ec
const ec = new EC('p256');
const ecUtils = require('eckey-utils')
const eccrypto = require("eccrypto")
const bigInt = require("big-integer");


function handleEcdhParam(decArray) {
  const hexStrArray = decArray.map(num => {
    const hex = num.toString(16);
    return (hex.length < 2) ? '0' + hex : hex;
  });
  const hexString = hexStrArray.join("");
  const switchedHexString = switchEndian(hexString);
  const decimalString = bigInt(switchedHexString, 16).toString();
  return decimalString;
}


function getMsg2(ecPublicKey, session) {
    /* Get GAX */
    const gax = ecPublicKey.X
    const gay = ecPublicKey.Y
    const key = ec.genKeyPair()
    const gbx = switchEndian(key.getPublic().getX().toString(16))
    const gby = switchEndian(key.getPublic().getY().toString(16))

    /* Generate msg2 */
    const signKey = ec.keyFromPrivate(signPriKey)
    // Get server public key
    const sgxPubKey = {
        x: gax,
        y: gay,
    }
    const sgxKey = ec.keyFromPublic(sgxPubKey,'hex')

    /**
     * Generate smk
     * */ 
    const sharedKey = switchEndian(toHex(key.derive(sgxKey.getPublic())))
    //console.log("sharedKey          = ",sharedKey)
    const iv = Buffer.alloc(16, 0)
    const kdk = aesCmac(iv, hexString2Buffer(sharedKey))
    //console.log("kdk                = ",kdk)
    // derive smk
    const message = [0x01,'S'.charCodeAt(0),'M'.charCodeAt(0),'K'.charCodeAt(0),0x00,0x80,0x00]
    const smk = aesCmac(hexString2Buffer(kdk), Buffer.from(message))
    //console.log("smk                = ",smk)

    /**
     * @desc get signature: sign publck keys with my private key
     */
    const GBA = gbx+gby+switchEndian(gax)+switchEndian(gay)
    //console.log("GBA                = ",GBA)
    const digest = crypto.createHash('sha256')
            .update(hexString2Buffer(GBA))
            .digest()
    //console.log("digest             = ", buf2hexString(digest))

    // use elliptic
    const sig = signKey.sign(digest)
    const SigSPX = switchEndian(toHex(sig.r))
    const SigSPY = switchEndian(toHex(sig.s))
    //console.log("unreverse SigSPX   = ", sig.r.toString(16))
    //console.log("unreverse SigSPY   = ", sig.s.toString(16))
    //console.log("SigSPX             = ", SigSPX)
    //console.log("SigSPY             = ", SigSPY)

    /* 
     * derive CMACsmk 
     * */
    const QUOTE_TYPE = "0100"
    const KDF_ID = "0100"
    const A = gbx + gby + SPID + QUOTE_TYPE + KDF_ID + SigSPX + SigSPY
    const CMACsmk = aesCmac(hexString2Buffer(smk), hexString2Buffer(A))
    //console.log("CMACsmk            = ", CMACsmk)

    /**
     * @Set session info
     * */
    session["ga"] = {
        gax: gax,
        gay: gay
    }
    session["smk"] = smk
    session["sharedKey"] = sharedKey

  /**
   * @desc get smac
   */
    return {
        type: "msg2",
        status: "successfully",
        gbx: gbx,
        gby: gby,
        quoteType: QUOTE_TYPE,
        spid: SPID,
        kdfId: KDF_ID,
        SigSPX: SigSPX,
        SigSPY: SigSPY,
        CMACsmk: CMACsmk,
        sizeSigrl: SIZE_SIGRL,
        sigrl: SIGRL
    }
}

module.exports = {
    getMsg2: getMsg2,
}

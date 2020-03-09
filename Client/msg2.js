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
    //const gax = switchEndian("04771151353fb74ff97de214f1b5795fcfd4fd62d0f662371d0e21fbf9df1020")
    //const gay = switchEndian("e391d3c437c83ad50f1359b9c3235ae86ebcf8a7d117b7cfa5dd2a292dbf40e2")
    //const gbx = "b8810357841249f28029c3477dd051aa617061edabfa0dd3574731c355295f8c"
    //const gby = "abca295ab9fdc4ff4fa17147ec67f72b177658029218d32cea2c5f363f3da01f"
    //const priKey = "DF43CC1A7ED4A6259EF2634F32FB489D3D8D6F276AD91C52FCE90FAE19B3B6A6"
    //const key = ec.keyFromPrivate(priKey)
    
    const gax = ecPublicKey.X
    const gay = ecPublicKey.Y
    const key = ec.genKeyPair()
    const gbx = switchEndian(key.getPublic().getX().toString(16))
    const gby = switchEndian(key.getPublic().getY().toString(16))

    /* Generate msg2 */
    console.log("===== gax", gax)
    console.log("===== gay", gay)
    console.log("===== key publicx", key.getPublic().getX().toString(16))
    console.log("===== key publicy", key.getPublic().getY().toString(16))
    const signPriKey = "018C03D1533457ADEAAEB6653B6A861FEC879C4311DE663BCEA1522DBB6CE790"
    const signKey = ec.keyFromPrivate(signPriKey)
    console.log("===== sign publicx", signKey.getPublic().getX().toString(16))
    console.log("===== sign publicy", signKey.getPublic().getY().toString(16))
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
    console.log("sharedKey",sharedKey)
    const iv = Buffer.alloc(16, 0)
    const kdk = aesCmac(iv, hexString2Buffer(sharedKey))
    console.log("======kdk",kdk)
    // derive smk
    const message = [0x01,'S'.charCodeAt(0),'M'.charCodeAt(0),'K'.charCodeAt(0),0x00,0x80,0x00]
    const smk = aesCmac(hexString2Buffer(kdk), Buffer.from(message))
    console.log("======smk",smk)

    /**
     * @desc get signature: sign publck keys with my private key
     */
    const GBA = gbx+gby+switchEndian(gax)+switchEndian(gay)
    console.log("=====GBA",GBA)
    const digest = crypto.createHash('sha256')
            .update(hexString2Buffer(GBA))
            .digest()
    console.log("===== digest", buf2hexString(digest))

    // use elliptic
    const sig = signKey.sign(digest)
    const SigSPX = switchEndian(toHex(sig.r))
    const SigSPY = switchEndian(toHex(sig.s))
    console.log("===== unreverse SigSPX", sig.r.toString(16))
    console.log("===== unreverse SigSPY", sig.s.toString(16))
    console.log("===== SigSPX", SigSPX)
    console.log("===== SigSPY", SigSPY)

    /* 
     * derive CMACsmk 
     * */
    const QUOTE_TYPE = "0100"
    const KDF_ID = "0100"
    const A = gbx + gby + SPID + QUOTE_TYPE + KDF_ID + SigSPX + SigSPY
    const CMACsmk = aesCmac(hexString2Buffer(smk), hexString2Buffer(A))
    console.log("=====A", A)
    console.log("=====CMACsmk", CMACsmk)

    /**
     * @Set session info
     * */
    session["ga"] = {
        gax: gax,
        gay: gay
    }
    session["smk"] = smk

  /**
   * @desc get smac
   */
    return {
        type: "msg2",
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

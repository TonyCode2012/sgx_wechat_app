//const {
//  SPID,
//  SIGRL,
//  SIZE_SIGRL,
//  AES_CMAC_KDF_ID,
//  SAMPLE_QUOTE_LINKABLE_SIGNATURE
//} =  require("./ecConstants");
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
//const ec = crypto.createECDH('secp256k1')
const aesCmac = require("node-aes-cmac").aesCmac;
const EC = require('elliptic').ec
const ec = new EC('p256');
//const ec = new EC('secp256k1');
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


function getMsg2(ecPublicKey) {
    //const GAX = hexStringToArray(ecPublicKey.X,2)
    //const GAY = hexStringToArray(ecPublicKey.Y,2)
    const gax_o = "8f6405f2bc7b7d3c66eb9dfcdaeb1ab19867d528b85426fab9f4459d3f6a715e"
    const gay_o = "60bb87cc172220380294e0ddbb8e92ea2ba63a3eb99ebd6c659a07c8d39977ed"
    const gax = switchEndian(gax_o)
    const gay = switchEndian(gay_o)
    const GAX = hexStringToArray(gax,2)
    const GAY = hexStringToArray(gay,2)

    /* Generate msg2 */
    const gbx = "68d4d7c82d4dd8a72de568da4989fc95076745a13a612164c30a208958ef0485"
    const gby = "55edd100abc57249157f174c78cd4863a5daa161b812a0f3e19eb0a36fce06e7"
    //const gbx = switchEndian("38b9fc97433e342ada6d1aacf8b5eec04515ca4ef4ef4602fdb436facf0a4b7d")
    //const gby = switchEndian("a1bb2339bd6b39965d08d4b31bd9d2a875cf165e6f00895779691cfcc9208a1a")
    const GBX = hexStringToArray(gbx,2)
    const GBY = hexStringToArray(gby,2)
    const pubKey = {
        x: gbx,
        y: gby,
    }
    //const signPriKey = "90e76cbb2d52a1ce3b66de11439c87ec1f866a3b65b6aeeaad573453d1038c01"
    const signPriKey = "18C03D1533457ADEAAEB6653B6A861FEC879C4311DE663BCEA1522DBB6CE790"
    //const signPriKey = switchEndian("18C03D1533457ADEAAEB6653B6A861FEC879C4311DE663BCEA1522DBB6CE790")
    const priKey = "85DDC3B7C45F40F7DD97C543A61524B6C6E34975C68C0AA981F7363447BB0DD4"
    const signKey = ec.keyFromPrivate(signPriKey)
    const key = ec.keyFromPrivate(priKey)
    //const key_pub = ec.keyFromPublic(pubKey)
    console.log("=====signpubkey",signKey.getPublic().getX().toString(16))
    console.log("=====signpubkey",signKey.getPublic().getY().toString(16))
    //console.log("=====pubkey",key.getPublic())
    //const key = ec.genKeyPair()
    const MY_PRIVATE_KEY = key.getPrivate()
    const MY_PUBLIC_KEY = key.getPublic()
    //const GBX = hexStringToArray(MY_PUBLIC_KEY.getX().toString(16),2)
    //const GBY = hexStringToArray(MY_PUBLIC_KEY.getY().toString(16),2)
    //console.log("pubkey:",MY_PUBLIC_KEY.getX())

    // Get server public key
    const serverPubKey = {
        //x: ecPublicKey.X,
        //y: ecPublicKey.Y
        x: gax,
        y: gay,
    }
    const serverKey = ec.keyFromPublic(serverPubKey,'hex')
    //console.log("server key",serverKey)

    // derive kdk
    const sharedKey = switchEndian(toHex(key.derive(serverKey.getPublic())))
    //console.log("sharedKey",key.derive(serverKey.getPublic()))
    console.log("sharedKey",sharedKey)
    const iv = Buffer.alloc(16, 0)
    //const cipher = crypto.createCipheriv('aes-128-cbc', iv, iv)
    //cipher.update(Buffer.from(hexStringToArray(sharedKey,2)), 'hex', 'hex')
    //cipher.update(sharedKey, 'hex', 'hex')
    const kdk = aesCmac(iv, hexString2Buffer(sharedKey))
    //const kdk_hex = cipher.final('hex')
    //const kdk = Buffer.from(hexStringToArray(kdk_hex, 2))
    //const kdk = Buffer.from(hexStringToArray(cipher.final('hex'), 2))
    console.log("======kdk",kdk)
    // derive smk
    //const message = 0x01+'S'+'M'+'K'+0x00+0x80+0x00
    const message = [0x01,'S'.charCodeAt(0),'M'.charCodeAt(0),'K'.charCodeAt(0),0x00,0x80,0x00]
    const smk = aesCmac(hexString2Buffer(kdk), Buffer.from(message))
    console.log("======smk",smk)
    //console.log("message",message)
    //const cipher2 = crypto.createCipheriv('aes-128-cbc', kdk, iv)
    //cipher2.update(Buffer.from(message), 'utf8', 'hex')
    //const smk = hexStringToArray(cipher2.final('hex'), 2)

    /**
     * @desc get signature: sign publck keys with my private key
     */
    const GBA = gbx+gby+gax_o+gay_o
    console.log("=====GBA",GBA)
    const digest = crypto.createHash('sha256')
            .update(hexString2Buffer(GBA))
            .digest()
    console.log("===== digest",digest)
    console.log("===== digest",buf2hexString(digest))
    
    const rs = require('jsrsasign')
    const KJUREC = new rs.KJUR.crypto.ECDSA({'curve': 'prime256v1'})
    const KJURSIG = KJUREC.signHex(buf2hexString(digest), signPriKey)
    console.log("===== KJURSIG:", KJURSIG)

    const sign_t = crypto.createSign('SHA256')
    sign_t.write(GBA)
    sign_t.end()
    //const ttt = '-----BEGIN EC PRIVATE KEY-----\n' +
    //    'MD4CAQEEIBjAPRUzRXrequtmU7aoYf7IecQxHeZjvOoVItu2znkAoAoGCCqGSM49\n' +
    //    ' AwEHoQsDCQAAC+wAAAAMAA==\n' +
    //    ' -----END EC PRIVATE KEY-----'
    //const tmp3 = sign_t.sign(ttt, 'hex')
    //const ttt = crypto.createPrivateKey(signPriKey)
    //const tmp3 = sign_t.sign(ttt, 'hex')
    const my_keypair = crypto.generateKeyPairSync('ec', {
        namedCurve:'P-256',
        //namedCurve:'prime256v1',
        privateKeyEncoding : {
            type: 'pkcs8',
            format: 'pem'
        }
    })
    const pems = ecUtils.generatePem({
        curveName: 'prime256v1',
        privateKey: hexString2Buffer(toHex(signKey.getPrivate())),
        publicKey: hexString2Buffer(toHex(signKey.getPublic()))
    })
    //console.log("===== tmp3:", my_keypair.privateKey)
    //console.log("===== tmp3:", pems.privateKey)
    //console.log("===== tmp3:", tmp3)

    //const sig = signKey.sign(Array.from(digest))
    const sig = signKey.sign(Array.from(digest))
    const SigSPX = toHex(sig.r)
    const SigSPY = toHex(sig.s)
    //console.log("SigSPX", sig.r.toString(16))
    //console.log("SigSPX", buf2hexString(sig.toDER()))
    console.log("===== SigSPX", bigInt(sig.r).toString(16))
    console.log("===== SigSPY", sig.s.toString(16))
    console.log("===== SigSPY", bigInt('387a059f2330aff862bcf7cd572f67f596ad77ee6b4f0bd1e0e06de9d6f90d93', 16).toString(16))
    //console.log("=====   elliptic",sig.r)
    //console.log("=====   elliptic",sig.s)
    //const sig = signKey.sign(Buffer.from(hexStringToArray(digest,2)))
    //const sig = signKey.sign(Buffer.from(hexStringToArray(GBA,2)))
    //const sign_x = key.sign(GBAY);
    //const sign_y = key.sign(GBAY);
    //const SigSPX = sign_x.toDER();
    //const SigSPY = sign_y.toDER();
    
    eccrypto.sign(hexString2Buffer(signPriKey), digest).then(function(sig){
        console.log("===== tmp:", buf2hexString(sig))
    })
    //const tmp2 = ec.sign(digest, hexString2Buffer(signPriKey), {canonical:true})
    const tmp2 = ec.sign(Array.from(digest), signPriKey)
    console.log("=====   tmp2",toHex(tmp2.r))
    console.log("=====   tmp2",toHex(tmp2.s))
    // derive CMACsmk
    const QUOTE_TYPE = [0x00,0x01]
    const KDF_ID = [0x00,0x01]
    const SPID_ARRY = hexStringToArray(SPID, 2)
    const A = GBX.concat(GBY).concat(SPID_ARRY).concat(QUOTE_TYPE).concat(KDF_ID).concat(SigSPX).concat(SigSPY)
    
    //const cipher3 = crypto.createCipheriv('aes-128-cbc', Buffer.from(smk), iv)
    //cipher3.update(toHex(A), 'utf8', 'hex')
    //const CMACsmk = cipher3.final('hex')
    const CMACsmk = aesCmac(Buffer.from(hexStringToArray(smk,2)), Buffer.from(A))
    console.log("=====CMACsmk", CMACsmk)
    console.log("SigSPX", toHex(MY_PUBLIC_KEY.getX()))

  /**
   * @desc get smac
   */
  //const GBX = toHex(MY_PUBLIC_KEY.X);
  //const GBY = toHex(MY_PUBLIC_KEY.Y);
  //const sMyPublicKey = switchEndian(bigInt(MY_PUBLIC_KEY.X).toString(16), 2) + switchEndian(bigInt(MY_PUBLIC_KEY.Y).toString(16), 2);

    //const smac = aesCmac(SHORT_KEY, sMyPublicKey);
    return {
        type: "msg2",
        gbx: switchEndian(MY_PUBLIC_KEY.getX().toString(16)),
        gby: switchEndian(MY_PUBLIC_KEY.getY().toString(16)),
        //gbx: MY_PUBLIC_KEY.getX().toString(16),
        //gby: MY_PUBLIC_KEY.getY().toString(16),
        quoteType: buf2hexString(switchEndian(QUOTE_TYPE)),
        spid: SPID,
        kdfId: buf2hexString(switchEndian(KDF_ID)),
        SigSPX: buf2hexString(switchEndian(SigSPX)),
        SigSPY: buf2hexString(switchEndian(SigSPY)),
        CMACsmk: CMACsmk,
        sizeSigrl: SIZE_SIGRL,
        sigrl: SIGRL
    }
}

module.exports = {
    getMsg2: getMsg2,
}

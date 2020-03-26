const SIGRL = 0;
const SIZE_SIGRL = 0;
const {
    switchEndian,
    toHex,
    hexStringToArray,
    buf2hexString,
    hexString2Buffer,
    httpSend,
} = require("./utils");
const {
    signPriKey,
    SPID,
    iasBaseUrl,
    iasHeader,
} = require("./config")

const crypto = require("crypto")
const aesCmac = require("node-aes-cmac").aesCmac;
const EC = require('elliptic').ec
const ec = new EC('p256');



async function getMsg2(ecPublicKey, session) {
    /* Get sigrl */
    console.log("\n===== Requesting SigRL from IAS... ======")
    var sigrl = ""
    var sigrlSize = 0
    const sigRet = await httpSend(iasBaseUrl+"/sigrl/"+switchEndian(session.gid),"GET",iasHeader,"")
    if (sigRet.statusCode != 200)
    {
        console.log("Request IAS server failed!")
        return null
    }
    if (sigRet.body != undefined && sigRet.body != "")
    {
        sigrl = sigRet.body
        sigrlSize = sigrl.length
    }

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
    // Derive smk
    const message = [0x01,'S'.charCodeAt(0),'M'.charCodeAt(0),'K'.charCodeAt(0),0x00,0x80,0x00]
    const smk = aesCmac(hexString2Buffer(kdk), Buffer.from(message))
    //console.log("smk                = ",smk)
    // Derive sk and mk
    const skMsg = [0x01,'S'.charCodeAt(0),'K'.charCodeAt(0),0x00,0x80,0x00]
    const mkMsg = [0x01,'M'.charCodeAt(0),'K'.charCodeAt(0),0x00,0x80,0x00]
    const sk = aesCmac(hexString2Buffer(kdk), Buffer.from(skMsg))
    const mk = aesCmac(hexString2Buffer(kdk), Buffer.from(mkMsg))

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
    session["kdk"] = kdk
    session["smk"] = smk
    session["sk"] = sk
    session["mk"] = mk
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
        sizeSigrl: sigrlSize,
        sigrl: sigrl,
    }
}

module.exports = {
    getMsg2: getMsg2,
}

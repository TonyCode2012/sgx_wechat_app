const {
    iasBaseUrl,
    iasHeader,
} = require("./config")
const {
    switchEndian,
    buf2hexString,
    hexString2Buffer,
    base64Encode,
    httpSend,
} = require("./utils")
const aesCmac = require("node-aes-cmac").aesCmac
const Base64 = require("js-base64").Base64

async function getMsg4(msg3, session) {
    // Compare public key
    console.log("===== session", session)
    const gax = switchEndian(msg3.gax)
    const gay = switchEndian(msg3.gay)
    if (gax != session.ga.gax || gay != session.ga.gay)
    {
        console.log("Wrong server public key!")
        return null
    }

    // Compare gid
    const epid_group_id = msg3.quote.substr(8,8)
    if (epid_group_id != session.gid)
    {
        console.log("Wrong epid!")
        return null
    }

    // Compare mac
    const vrfydata = msg3.gax + msg3.gay + msg3.ps_sec_prop + msg3.quote
    const vrfymac = aesCmac(hexString2Buffer(session.smk), hexString2Buffer(vrfydata))
    if (msg3.mac != vrfymac)
    {
        console.log("Wrong mac!")
        return null
    }

    // Send quote to IAS
    const b64quote = Base64.encode(hexString2Buffer(msg3.quote))
    const body = {
        "isvEnclaveQuote": b64quote
    }
    console.log("===== b64quote",b64quote)
    console.log("===== iasurl",iasBaseUrl+"/report")
    console.log("===== iasheader",iasHeader)
    const iasResponse = await httpSend(iasBaseUrl+"/report",iasHeader,body)
    if (iasResponse.statusCode != 200)
    {
        console.log("Request IAS service failed!")
        return null
    }
    console.log("\n===== Verify Quote successfully =====\n")
    console.log(iasResponse.body)
}

module.exports = {
    getMsg4 : getMsg4,
}

const iasurl = "https://api.trustedservices.intel.com/sgx/dev/attestation/v3/entry/network"
const header_key = "Ocp-Apim-Subscription-Key"
const header_val = "e2e08166ca0f41ef88af2797f007c7cd"

function getMsg4(msg3, session) {
    // Compare public key
    if (msg3.gax != session.gax && msg3.gay != session.gay)
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
    const vrfydata = msg3.gax + msg3.gay + msg3.ps_sec_prop
    const vrfymac = aesCmac(hexString2Buffer(session.smk), 
        hexString2Buffer(vrfydata))
    if (msg3.mac != vrfymac)
    {
        console.log("Wrong mac!")
        return null
    }

    // Send quote to IAS
    const b64quote = base64Encode(msg.quote)
}

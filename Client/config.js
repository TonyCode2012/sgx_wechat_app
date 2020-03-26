const srvurl = "http://localhost:12345";
const iasBaseUrl = "https://api.trustedservices.intel.com/sgx/dev/attestation/v3"
const iasHeader = { "Ocp-Apim-Subscription-Key": "e2e08166ca0f41ef88af2797f007c7cd"}
const signPriKey = "018C03D1533457ADEAAEB6653B6A861FEC879C4311DE663BCEA1522DBB6CE790"
const SPID = "FEF23C7E73A379823CE71FF289CFBC07"
const AES_CMAC_KDF_ID = 0x0001
const SAMPLE_QUOTE_LINKABLE_SIGNATURE = 1

module.exports = {
    srvurl : srvurl,
    iasBaseUrl : iasBaseUrl,
    iasHeader : iasHeader,
    signPriKey : signPriKey,
    SPID : SPID,
    AES_CMAC_KDF_ID : AES_CMAC_KDF_ID,
    SAMPLE_QUOTE_LINKABLE_SIGNATURE : SAMPLE_QUOTE_LINKABLE_SIGNATURE,
}

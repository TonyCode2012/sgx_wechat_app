const srvurl = "http://localhost:12345";
const iasBaseUrl = "https://api.trustedservices.intel.com/sgx/dev/attestation/v3"
const iasHeader = { "Ocp-Apim-Subscription-Key": "e2e08166ca0f41ef88af2797f007c7cd"}

module.exports = {
    srvurl : srvurl,
    iasBaseUrl : iasBaseUrl,
    iasHeader : iasHeader,
}

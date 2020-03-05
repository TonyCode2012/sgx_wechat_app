const getMsg2 = require('./msg2').getMsg2
const request = require('request');
const bigInt = require("big-integer");
//var url="http://127.0.0.0:12345";
const url="http://localhost:12345";
const sigurl = "https://api.trustedservices.intel.com/sgx/dev/attestation/v3/sigrl/000013d6"
var msg0 = {
    "type": "msg0",
    "name" : "yaoz",
    "age" : 44,
};
 
const send = function(data) {
    return new Promise(function(resolve, reject) {
        request({
            url: url,
            method: "POST",
            json: true,
            headers: {
                "content-type": "application/json",
                //"Ocp-Apim-Subscription-Key": "e2e08166ca0f41ef88af2797f007c7cd",
            },
            body: data
        }, function(error, response, body) {
            if (!error && response.statusCode == 200) {
                console.log("successful:",body) // 请求成功的处理逻辑
                resolve(body)
            } else {
                console.log("failed:",error) // 请求成功的处理逻辑
                reject(error)
            }
        });
    })
};
 
main()

async function main() {
    const msg1 = await send(msg0)
    console.log("msg1",msg1)
    const msg2 = getMsg2({
        X : msg1.gax,
        Y : msg1.gay,
    })
    console.log("msg2",msg2)
    const msg3 = send(msg2)
    //assemble(msg3)
}

import {
    srvurl,
    iasurl,
} from "config" 

import {
    httpSend,
} from "utils"

const getMsg2 = require('./msg2').getMsg2
const getMsg4 = require('./msg4').getMsg4
const msg0 = {
    "type": "msg0",
    "name" : "yaoz",
    "age" : 44,
};

async function main() {
    const msg1 = await httpSend(srvurl, msg0)
    var session = {}
    session["gid"] = buf2hexString(switchEndian(hexString2Buffer(msg1.gid)))
    console.log("msg1",msg1)
    if (msg1.status == 'failed')
    {
        console.log("Get msg1 failed");
        return
    }
    const msg2 = getMsg2({
        X : msg1.gax,
        Y : msg1.gay,
    }, session)
    console.log("msg2",msg2)
    const msg3 = httpSend(srvurl, msg2)
    if (msg3.status == 'failed')
    {
        console.log("Get msg3 failed");
        return
    }
    const msg4 = getMes4(msg3,session)
}
 
main()

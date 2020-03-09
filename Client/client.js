const { 
    srvurl,
    iasurl,
} = require("./config")
const {
    httpSend,
    buf2hexString,
    hexString2Buffer,
    switchEndian,
} = require("./utils")
const getMsg2 = require('./msg2').getMsg2
const getMsg4 = require('./msg4').getMsg4
const msg0 = {
    "type": "msg0",
    "name" : "yaoz",
    "age" : 44,
};

async function main() {
    var session = {}
    // Send msg0 and get msg1
    const { body, statusCode1 } = await httpSend(srvurl,null,msg0)
    if (statusCode1 != 200 || msg1.status == 'failed')
    {
        console.log("Get msg1 failed");
        return
    }
    session["gid"] = switchEndian(msg1.gid)
    console.log("===== Msg1 Detail =====")
    console.log(msg1)
    // Get msg2 from msg1
    const msg2 = getMsg2({
        X : msg1.gax,
        Y : msg1.gay,
    }, session)
    console.log("msg2",msg2)
    // Send msg2 and get msg3
    const { msg3, statusCode3 } = await httpSend(srvurl,null,msg2)
    if (statusCode3 != 200 || msg3.status == 'failed')
    {
        console.log("Get msg3 failed");
        return
    }
    console.log("===== Msg3 Detail =====")
    console.log(msg3)
    // Get msg4 from msg3
    const msg4 = getMsg4(msg3,session)
}
 
main()

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
};

async function main() {
    var session = {}
    /* Send msg0 and get msg1 */
    const res1 = await httpSend(srvurl,"POST",null,msg0)
    const msg1 = res1.body
    if (res1.statusCode != 200 || msg1.status == 'failed')
    {
        console.log("Get msg1 failed");
        return
    }
    session["gid"] = switchEndian(msg1.gid)
    console.log("\n===== Msg1 Detail =====")
    console.log(msg1)
    // Get msg2 from msg1
    const msg2 = await getMsg2({
        X : msg1.gax,
        Y : msg1.gay,
    }, session)
    console.log("\n===== Msg2 Detail =====")
    console.log(msg2)

    /* Send msg2 and get msg3 */
    const res2 = await httpSend(srvurl,"POST",null,msg2)
    const msg3 = res2.body
    if (res2.statusCode != 200 || msg3.status == 'failed')
    {
        console.log("Get msg3 failed");
        return
    }
    console.log("\n===== Msg3 Detail =====")
    console.log(msg3)

    /* Get and Send msg4 */
    const msg4 = await getMsg4(msg3,session)
    console.log("\n===== Msg4 Detail =====")
    console.log(msg4)
    const res3 = await httpSend(srvurl,"POST",null,msg4)

    console.log("\n===== Response Detail =====")
    console.log(res3.body)
}
 
main()

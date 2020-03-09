const bigInt = require("big-integer");
const request = require('request');

/**
 * @method switchEndian
 * @param {String} string needed to be transformed
 * @returns {String} result
 */
function switchEndian(data) {
    if (typeof(data) == 'string') {
        if(data.length % 2) {
          data += '0'
        }
        var res = ""
        for(var i = data.length-2; i >= 0; i -= 2) {
            res += data.substr(i,2)
        }
        return res
    } else if(Array.isArray(data)) {
        return data.reverse()
    }

    return ""
}

/**
 * @method toHex
 * @param {String} input needed to be transformed
 * @returns {String} result
 */
function toHex(input) {
  return bigInt(input).toString(16);
}

/**
 * @method hexStringToArray
 * @param {String} str
 * @returns {Array} result
 */
function hexStringToArray(str, step) {
  let result = [];
    if(typeof(str) != 'string') {
        return result
    }
  if (str.length % step != 0){
      const gap = step - str.length % step
      str += "0".repeat(gap)
  } 
  //throw new Error();

  for (let i = 0; i < str.length; i = i + step) {
    const chunk = str.slice(i, i + step);
    const num = parseInt(chunk, 16);
    result.push(num);
  }

  return result;
}

function hexString2Buffer(str)
{
    return Buffer.from(hexStringToArray(str, 2))
}

function buf2hexString(buffer) { // buffer is an ArrayBuffer
  return Array.prototype.map.call(new Uint8Array(buffer), x => ('00'  + x.toString(16)).slice(-2)).join('');
}

function base64Encode(hexstring)
{
    hexString2Buffer(hexstring).toString('base64')
}

function base64Decode(base64string)
{
    return Buffer.from(base64string, 'base64').toString('ascii').toString(16)
}
 
function httpSend(url,data) {
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

module.exports = {
    switchEndian: switchEndian,
    toHex: toHex,
    hexStringToArray: hexStringToArray,
    buf2hexString: buf2hexString,
    hexString2Buffer: hexString2Buffer,
    httpSend: httpSend,
}

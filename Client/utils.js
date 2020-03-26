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
          data = '0' + data
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
 
function httpSend(url,method,header,data) {
    if (header == null)
    {
        header = {"content-type": "application/json"}
    }
    if (method != "POST" && method != "GET")
    {
        console.log("Wrong http method!Should be POST or GET!")
        return
    }
    return new Promise(function(resolve, reject) {
        request({
            url: url,
            method: method,
            json: true,
            headers: header,
            body: data
        }, function(error, response, body) {
            if (!error && response.statusCode == 200) {
                resolve({
                    body: body,
                    statusCode: response.statusCode,
                    response: response,
                })
            } else {
                reject({
                    statusCode: response.statusCode,
                })
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

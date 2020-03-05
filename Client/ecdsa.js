const asn1 = require('asn1'); 
const BN = require('bn'); 
const crypto = require('crypto'); 
const EcdsaDerSig = asn1.define('ECPrivateKey', function() { return this.seq().obj( this.key('r').int(), this.key('s').int() ); }); 
function asn1SigSigToConcatSig(asn1SigBuffer) { const rsSig = EcdsaDerSig.decode(asn1SigBuffer, 'der'); return Buffer.concat([ rsSig.r.toArrayLike(Buffer, 'be', 32), rsSig.s.toArrayLike(Buffer, 'be', 32) ]); } 

function concatSigToAsn1SigSig(concatSigBuffer) { const r = new BN(concatSigBuffer.slice(0, 32).toString('hex'), 16, 'be'); const s = new BN(concatSigBuffer.slice(32).toString('hex'), 16, 'be'); return EcdsaDerSig.encode({r, s}, 'der'); } 

function ecdsaSign(hashBuffer, key) { const sign = crypto.createSign('sha256'); sign.update(asBuffer(hashBuffer)); const asn1SigBuffer = sign.sign(key, 'buffer'); return asn1SigSigToConcatSig(asn1SigBuffer); } 

function ecdsaVerify(data, signature, key) { const verify = crypto.createVerify('SHA256'); verify.update(data); const asn1sig = concatSigToAsn1Sig(signature); return verify.verify(key, new Buffer(asn1sig, 'hex')); }

module.exports = {
    ecdsaSign: ecdsaSign,
}

function byteToHex(byte) {
    let out = byte.toString(16);
    if (out.length === 1) out = "0" + out;
    return out;
}

module.exports = { byteToHex };

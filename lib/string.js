function byteStringToBytes(byteString) {
    if (typeof byteString !== "string") return null;
    if (!byteString.startsWith("0x")) return null;

    const a_CHAR_CODE = "a".charCodeAt(0);
    const f_CHAR_CODE = "f".charCodeAt(0);
    const A_CHAR_CODE = "A".charCodeAt(0);
    const F_CHAR_CODE = "F".charCodeAt(0);

    const ZERO_CHAR_CODE = "0".charCodeAt(0);
    const NINE_CHAR_CODE = "9".charCodeAt(0);

    function letterToNumber(letter) {
        let l = letter.charCodeAt(0);
        if (l >= a_CHAR_CODE && l <= f_CHAR_CODE) l = l - a_CHAR_CODE + 10;
        else if (l >= A_CHAR_CODE && l <= F_CHAR_CODE) l = l - A_CHAR_CODE + 10;
        else if (l >= ZERO_CHAR_CODE && l <= NINE_CHAR_CODE)
            l -= ZERO_CHAR_CODE;
        else {
            throw new Error(`Invalid hex character ${letter}`);
        }

        return l;
    }

    let length = 0;
    let currentBigram = [];
    let bytes;
    {
        const byteSize = (byteString.length - 2) / 2;
        bytes = new Uint8Array(byteSize);
    }

    for (let i = 2; i < byteString.length; i++) {
        const endOfByte = i % 2 == 1;
        currentBigram[i % 2] = byteString[i];

        if (endOfByte) {
            let a = letterToNumber(currentBigram[0]);
            let b = letterToNumber(currentBigram[1]);

            const byte = (a << 4) | b;

            bytes[length++] = byte;
            currentBigram = [];
        }
    }

    return bytes;
}

function byteToHex(byte) {
    let out = byte.toString(16);
    if (out.length === 1) out = "0" + out;
    return out;
}

module.exports = { byteStringToBytes, byteToHex };

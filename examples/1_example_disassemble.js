const disassembler = require("../index");

const BYTECODE =
    "0x608060405234801561001057600080fd5b50600436106100365760003560e01c806357de26a41461003b578063d09de08a14610059575b600080fd5b610043610063565b604051610050919061009c565b60405180910390f35b61006161006c565b005b60008054905090565b600160005461007b91906100e6565b600081905550565b6000819050919050565b61009681610083565b82525050565b60006020820190506100b1600083018461008d565b92915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b60006100f182610083565b91506100fc83610083565b9250828201905080821115610114576101136100b7565b5b9291505056fea2646970667358221220b6ab24c13c6cda0b644dfc989c0d2a21c12611547602bde8a254f33c3598539b64736f6c63430008110033";

const disassembly = disassembler.disassemble(BYTECODE);

console.log("'disassembly' object structure:");
console.log(Object.keys(disassembly));
console.log();

console.log("[INFO]");

console.log("   ", disassembly.opcodes.length, "opcodes");
console.log("   ", Object.keys(disassembly.labels).length, "code labels");
console.log("   ", disassembly.jumps.length, "jumps");
console.log("   ", disassembly.functions.length, "functions");
console.log("   ", disassembly.errors.length, "errors");
console.log();

console.log("[DISASSEMBLY]");

for (let i = 0; i < Math.min(disassembly.opcodes.length, 16); i++) {
    const op = disassembly.opcodes[i];
    console.log("   ", op.readableOutput);
}

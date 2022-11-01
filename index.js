/*
    evm-disasm-js
    - the goal is to write a fast disasembler with little to no dependencies
    - and decorate the code with helpers for common EVM bytecode structures
    - in the future, a decompiler could be provided as well
*/

const { byteStringToBytes, byteToHex } = require("./lib/string.js");

function fmtPush(n, mem, idx) {
    let out = "";
    for (let i = 0; i < n; i++) {
        if (idx + i + 1 < mem.length) {
            byte = mem[idx + i + 1];
            out = out + byteToHex(byte);
        }
    }

    return "0x" + out;
}

const instructionsTable = [];
{
    // The instructions table is generated from https://ethervm.io
    const t = instructionsTable;

    t[0x00] = ["STOP", 1, null];
    t[0x01] = ["ADD", 1, null];
    t[0x02] = ["MUL", 1, null];
    t[0x03] = ["SUB", 1, null];
    t[0x04] = ["DIV", 1, null];
    t[0x05] = ["SDIV", 1, null];
    t[0x06] = ["MOD", 1, null];
    t[0x07] = ["SMOD", 1, null];
    t[0x08] = ["ADDMOD", 1, null];
    t[0x09] = ["MULMOD", 1, null];
    t[0x0a] = ["EXP", 1, null];
    t[0x0b] = ["SIGNEXTEND", 1, null];
    t[0x0c] = [null, 1, null];
    t[0x0d] = [null, 1, null];
    t[0x0e] = [null, 1, null];
    t[0x0f] = [null, 1, null];
    t[0x10] = ["LT", 1, null];
    t[0x11] = ["GT", 1, null];
    t[0x12] = ["SLT", 1, null];
    t[0x13] = ["SGT", 1, null];
    t[0x14] = ["EQ", 1, null];
    t[0x15] = ["ISZERO", 1, null];
    t[0x16] = ["AND", 1, null];
    t[0x17] = ["OR", 1, null];
    t[0x18] = ["XOR", 1, null];
    t[0x19] = ["NOT", 1, null];
    t[0x1a] = ["BYTE", 1, null];
    t[0x1b] = ["SHL", 1, null];
    t[0x1c] = ["SHR", 1, null];
    t[0x1d] = ["SAR", 1, null];
    t[0x1e] = [null, 1, null];
    t[0x1f] = [null, 1, null];
    t[0x20] = ["SHA3", 1, null];
    t[0x21] = [null, 1, null];
    t[0x22] = [null, 1, null];
    t[0x23] = [null, 1, null];
    t[0x24] = [null, 1, null];
    t[0x25] = [null, 1, null];
    t[0x26] = [null, 1, null];
    t[0x27] = [null, 1, null];
    t[0x28] = [null, 1, null];
    t[0x29] = [null, 1, null];
    t[0x2a] = [null, 1, null];
    t[0x2b] = [null, 1, null];
    t[0x2c] = [null, 1, null];
    t[0x2d] = [null, 1, null];
    t[0x2e] = [null, 1, null];
    t[0x2f] = [null, 1, null];
    t[0x30] = ["ADDRESS", 1, null];
    t[0x31] = ["BALANCE", 1, null];
    t[0x32] = ["ORIGIN", 1, null];
    t[0x33] = ["CALLER", 1, null];
    t[0x34] = ["CALLVALUE", 1, null];
    t[0x35] = ["CALLDATALOAD", 1, null];
    t[0x36] = ["CALLDATASIZE", 1, null];
    t[0x37] = ["CALLDATACOPY", 1, null];
    t[0x38] = ["CODESIZE", 1, null];
    t[0x39] = ["CODECOPY", 1, null];
    t[0x3a] = ["GASPRICE", 1, null];
    t[0x3b] = ["EXTCODESIZE", 1, null];
    t[0x3c] = ["EXTCODECOPY", 1, null];
    t[0x3d] = ["RETURNDATASIZE", 1, null];
    t[0x3e] = ["RETURNDATACOPY", 1, null];
    t[0x3f] = ["EXTCODEHASH", 1, null];
    t[0x40] = ["BLOCKHASH", 1, null];
    t[0x41] = ["COINBASE", 1, null];
    t[0x42] = ["TIMESTAMP", 1, null];
    t[0x43] = ["NUMBER", 1, null];
    t[0x44] = ["DIFFICULTY", 1, null];
    t[0x45] = ["GASLIMIT", 1, null];
    t[0x46] = ["CHAINID", 1, null];
    t[0x47] = ["SELFBALANCE", 1, null];
    t[0x48] = ["BASEFEE", 1, null];
    t[0x49] = [null, 1, null];
    t[0x4a] = [null, 1, null];
    t[0x4b] = [null, 1, null];
    t[0x4c] = [null, 1, null];
    t[0x4d] = [null, 1, null];
    t[0x4e] = [null, 1, null];
    t[0x4f] = [null, 1, null];
    t[0x50] = ["POP", 1, null];
    t[0x51] = ["MLOAD", 1, null];
    t[0x52] = ["MSTORE", 1, null];
    t[0x53] = ["MSTORE8", 1, null];
    t[0x54] = ["SLOAD", 1, null];
    t[0x55] = ["SSTORE", 1, null];
    t[0x56] = ["JUMP", 1, null];
    t[0x57] = ["JUMPI", 1, null];
    t[0x58] = ["PC", 1, null];
    t[0x59] = ["MSIZE", 1, null];
    t[0x5a] = ["GAS", 1, null];
    t[0x5b] = ["JUMPDEST", 1, null];
    t[0x5c] = [null, 1, null];
    t[0x5d] = [null, 1, null];
    t[0x5e] = [null, 1, null];
    t[0x5f] = [null, 1, null];

    for (let i = 0; i < 32; i++) {
        t[0x60 + i] = [
            `PUSH${i + 1}`,
            i + 1 + 1,
            (mem, idx) => `${fmtPush(i + 1, mem, idx)}`,
        ];
    }

    t[0x80] = ["DUP1", 1, null];
    t[0x81] = ["DUP2", 1, null];
    t[0x82] = ["DUP3", 1, null];
    t[0x83] = ["DUP4", 1, null];
    t[0x84] = ["DUP5", 1, null];
    t[0x85] = ["DUP6", 1, null];
    t[0x86] = ["DUP7", 1, null];
    t[0x87] = ["DUP8", 1, null];
    t[0x88] = ["DUP9", 1, null];
    t[0x89] = ["DUP10", 1, null];
    t[0x8a] = ["DUP11", 1, null];
    t[0x8b] = ["DUP12", 1, null];
    t[0x8c] = ["DUP13", 1, null];
    t[0x8d] = ["DUP14", 1, null];
    t[0x8e] = ["DUP15", 1, null];
    t[0x8f] = ["DUP16", 1, null];
    t[0x90] = ["SWAP1", 1, null];
    t[0x91] = ["SWAP2", 1, null];
    t[0x92] = ["SWAP3", 1, null];
    t[0x93] = ["SWAP4", 1, null];
    t[0x94] = ["SWAP5", 1, null];
    t[0x95] = ["SWAP6", 1, null];
    t[0x96] = ["SWAP7", 1, null];
    t[0x97] = ["SWAP8", 1, null];
    t[0x98] = ["SWAP9", 1, null];
    t[0x99] = ["SWAP10", 1, null];
    t[0x9a] = ["SWAP11", 1, null];
    t[0x9b] = ["SWAP12", 1, null];
    t[0x9c] = ["SWAP13", 1, null];
    t[0x9d] = ["SWAP14", 1, null];
    t[0x9e] = ["SWAP15", 1, null];
    t[0x9f] = ["SWAP16", 1, null];
    t[0xa0] = ["LOG0", 1, null];
    t[0xa1] = ["LOG1", 1, null];
    t[0xa2] = ["LOG2", 1, null];
    t[0xa3] = ["LOG3", 1, null];
    t[0xa4] = ["LOG4", 1, null];
    t[0xa5] = [null, 1, null];
    t[0xa6] = [null, 1, null];
    t[0xa7] = [null, 1, null];
    t[0xa8] = [null, 1, null];
    t[0xa9] = [null, 1, null];
    t[0xaa] = [null, 1, null];
    t[0xab] = [null, 1, null];
    t[0xac] = [null, 1, null];
    t[0xad] = [null, 1, null];
    t[0xae] = [null, 1, null];
    t[0xaf] = [null, 1, null];
    t[0xb0] = ["PUSH", 1, null];
    t[0xb1] = ["DUP", 1, null];
    t[0xb2] = ["SWAP", 1, null];
    t[0xb3] = [null, 1, null];
    t[0xb4] = [null, 1, null];
    t[0xb5] = [null, 1, null];
    t[0xb6] = [null, 1, null];
    t[0xb7] = [null, 1, null];
    t[0xb8] = [null, 1, null];
    t[0xb9] = [null, 1, null];
    t[0xba] = [null, 1, null];
    t[0xbb] = [null, 1, null];
    t[0xbc] = [null, 1, null];
    t[0xbd] = [null, 1, null];
    t[0xbe] = [null, 1, null];
    t[0xbf] = [null, 1, null];
    t[0xc0] = [null, 1, null];
    t[0xc1] = [null, 1, null];
    t[0xc2] = [null, 1, null];
    t[0xc3] = [null, 1, null];
    t[0xc4] = [null, 1, null];
    t[0xc5] = [null, 1, null];
    t[0xc6] = [null, 1, null];
    t[0xc7] = [null, 1, null];
    t[0xc8] = [null, 1, null];
    t[0xc9] = [null, 1, null];
    t[0xca] = [null, 1, null];
    t[0xcb] = [null, 1, null];
    t[0xcc] = [null, 1, null];
    t[0xcd] = [null, 1, null];
    t[0xce] = [null, 1, null];
    t[0xcf] = [null, 1, null];
    t[0xd0] = [null, 1, null];
    t[0xd1] = [null, 1, null];
    t[0xd2] = [null, 1, null];
    t[0xd3] = [null, 1, null];
    t[0xd4] = [null, 1, null];
    t[0xd5] = [null, 1, null];
    t[0xd6] = [null, 1, null];
    t[0xd7] = [null, 1, null];
    t[0xd8] = [null, 1, null];
    t[0xd9] = [null, 1, null];
    t[0xda] = [null, 1, null];
    t[0xdb] = [null, 1, null];
    t[0xdc] = [null, 1, null];
    t[0xdd] = [null, 1, null];
    t[0xde] = [null, 1, null];
    t[0xdf] = [null, 1, null];
    t[0xe0] = [null, 1, null];
    t[0xe1] = [null, 1, null];
    t[0xe2] = [null, 1, null];
    t[0xe3] = [null, 1, null];
    t[0xe4] = [null, 1, null];
    t[0xe5] = [null, 1, null];
    t[0xe6] = [null, 1, null];
    t[0xe7] = [null, 1, null];
    t[0xe8] = [null, 1, null];
    t[0xe9] = [null, 1, null];
    t[0xea] = [null, 1, null];
    t[0xeb] = [null, 1, null];
    t[0xec] = [null, 1, null];
    t[0xed] = [null, 1, null];
    t[0xee] = [null, 1, null];
    t[0xef] = [null, 1, null];
    t[0xf0] = ["CREATE", 1, null];
    t[0xf1] = ["CALL", 1, null];
    t[0xf2] = ["CALLCODE", 1, null];
    t[0xf3] = ["RETURN", 1, null];
    t[0xf4] = ["DELEGATECALL", 1, null];
    t[0xf5] = ["CREATE2", 1, null];
    t[0xf6] = [null, 1, null];
    t[0xf7] = [null, 1, null];
    t[0xf8] = [null, 1, null];
    t[0xf9] = [null, 1, null];
    t[0xfa] = ["STATICCALL", 1, null];
    t[0xfb] = [null, 1, null];
    t[0xfc] = [null, 1, null];
    t[0xfd] = ["REVERT", 1, null];
    t[0xfe] = [null, 1, null];
    t[0xff] = ["SELFDESTRUCT", 1, null];
}

const [DISASM_INFO, DISASM_WARNING, DISASM_ERROR] = [0, 1, 2];
const c_disassemblyErrors = {
    INVALID_JUMPDEST: {
        severity: DISASM_WARNING,
        print: (error, data) =>
            `Opcode at 0x${data.addr.toString(
                16
            )} is not a valid jump destination.`,
    },
};

function addDisassemblyError(list, error) {
    const errorDescriptor = c_disassemblyErrors[error.code];
    if (!error.code) throw new Error("No disassembly error code", error.code);

    list.push({
        ...error,
        print: errorDescriptor.print.bind(null, error, error.data),
    });
}

/*
    Given an opcode index, returns the current code block by iterating backwards
    until a JUMPDEST is found
*/
function getCurrentCodeBlock(opcodes, opcodeIndex) {
    for (let i = opcodeIndex; i >= 0; i--) {
        const opcode = opcodes[i];
        if (!opcode) break;

        if (opcode.opcode === "JUMPDEST") {
            return i;
        }
    }

    return null;
}

/*
    TODO:
        - detect inputs / ouputs (for each code block, we can infer external inputs from the opcodes used)
        - detect program start
        - detect common structures such as function selector
*/
function disassemble(byteString) {
    const bytes = byteStringToBytes(byteString);
    const opcodes = [];
    const disassemblyErrors = [];
    const metadata = {};

    // Opcodes are indexed by the opcode index
    // Add a lookup table to index them by address
    let opcodesByAddr = {};

    // First pass: disassemble
    for (let i = 0; i < bytes.length; ) {
        const bytecode = bytes[i];
        const instructionData = instructionsTable[bytecode];
        if (!instructionData)
            throw new Error(`No instruction ${bytecode.toString(16)}`);

        const [opcode, advance, fmt] = instructionData;

        const operandString = fmt ? fmt(bytes, i) : "";
        const addr = i;

        i += advance;

        const readableOutput = `${addr.toString(16).toUpperCase()} ${
            opcode || byteToHex(bytecode).toUpperCase()
        } ${operandString}`;

        // Most instructions are one byte and take their operands from the stack
        // Except "PUSH" instructions which have another variable size constant
        let operandValue;
        if (opcode && opcode.startsWith("PUSH"))
            operandValue = BigInt(operandString); // TODO: needs bignum support

        const opcodeIndex = opcodes.length;

        opcodesByAddr[addr] = opcodeIndex;

        opcodes.push({
            addr,
            bytecode,
            opcode,
            readableOutput,
            operandValue,
        });
    }

    // Add jump labels
    const labels = {};
    const jumps = [];

    labels[0] = { name: "entry", addr: 0 };

    // We detect locations by looking at where JUMP & JUMPI instructions JUMP TO
    // We can combine this with a JUMPDEST analysis
    for (let i = 0; i < opcodes.length; i++) {
        const opcode = opcodes[i];
        const previousOpcode = opcodes[i - 1];

        if (
            previousOpcode &&
            previousOpcode.opcode === "PUSH2" &&
            (opcode.opcode === "JUMPI" || opcode.opcode === "JUMP")
        ) {
            // Read the instruction at the jump location and make sure there is a JUMPDEST
            const destinationOpcodeIndex =
                opcodesByAddr[previousOpcode.operandValue];
            const destinationOpcode = opcodes[destinationOpcodeIndex];

            // TODO: find ways to handle this error
            // If jump tests are invalid it could mean the code is not located properly
            // For example, if there is a constructor code in front of it
            if (!destinationOpcode) {
                addDisassemblyError(disassemblyErrors, {
                    code: "INVALID_JUMPDEST",
                    ...c_disassemblyErrors.INVALID_JUMPDEST,
                    data: { dest: null, addr: previousOpcode.operandValue },
                });

                metadata.hasInvalidJumpDest = true;
            } else if (destinationOpcode.opcode !== "JUMPDEST") {
                addDisassemblyError(disassemblyErrors, {
                    code: "INVALID_JUMPDEST",
                    ...c_disassemblyErrors.INVALID_JUMPDEST,
                    data: {
                        dest: destinationOpcode,
                        addr: previousOpcode.operandValue,
                    },
                });

                metadata.hasInvalidJumpDest = true;
            } else {
                const name = `loc_${previousOpcode.operandValue.toString(16)}`;
                labels[previousOpcode.operandValue] = {
                    name,
                    addr: previousOpcode.operandValue,
                    from: opcode.addr,
                };

                jumps.push({
                    addr: previousOpcode.operandValue,
                    from: opcode.addr,
                });
            }
        }
    }

    const functions = [];

    // Detect the function selector
    // This helps to add more precise names jump locations which are functions
    for (let i = 0; i < opcodes.length; i++) {
        const opcode = opcodes[i];
        const next = opcodes[i + 1];
        const afterNext = opcodes[i + 2];

        // Detect a sequence of "PUSH4/EQ/PUSH2"
        // The first value is the function hash and the second the jump location
        if (
            opcode.opcode === "PUSH4" &&
            next &&
            next.opcode === "EQ" &&
            afterNext &&
            afterNext.opcode === "PUSH2"
        ) {
            const func = {
                hash: opcode.operandValue,
                addr: afterNext.operandValue,
                name: `func_${opcode.operandValue.toString(16)}`,
            };

            functions.push(func);

            // When a function selector is found, we can mark the begining of the code block
            // containing it
            if (!metadata.hasFunctionSelector) {
                const functionSelectorStart = getCurrentCodeBlock(opcodes, i);
                const jumpdestOpcode = opcodes[functionSelectorStart];

                if (labels[jumpdestOpcode.addr]) {
                    labels[jumpdestOpcode.addr].name = "function_selector";
                    metadata.hasFunctionSelector = true;
                }
            }
        }
    }

    // Detect free memory pointers
    // This is useful to detect where is the start of the constructor
    // And where is the start of the contract deployed on chain
    const freeMemoryPointers = [];
    for (let i = 0; i < opcodes.length; i++) {
        const ops = [opcodes[i], opcodes[i + 1], opcodes[i + 2]];
        for (const op of ops) if (!op) break;

        if (
            ops[0].opcode === "PUSH1" &&
            ops[0].operandValue == 0x80 &&
            ops[1].opcode === "PUSH1" &&
            ops[1].operandValue == 0x40
        ) {
            freeMemoryPointers.push(ops[0].addr);
        }
    }

    if (freeMemoryPointers.length > 1) {
        metadata.seemsToHaveConstructorCode = true;
    }

    return {
        opcodes,
        labels,
        jumps,
        functions,
        errors: disassemblyErrors,
    };
}

function print(disassemblyOutput) {
    const strings = [];

    const functionsByAddr = {};
    for (const func of disassemblyOutput.functions) {
        functionsByAddr[func.addr] = func;
    }

    for (const e of disassemblyOutput.opcodes) {
        const label = disassemblyOutput.labels[e.addr];
        const func = functionsByAddr[e.addr];

        if (func) {
            console.log(`\n${func.name}:`);
            strings.push(`\n${func.name}:\n`);
        } else if (label) {
            console.log(`\n${label.name}:`);
            strings.push(`\n${label.name}:\n`);
        }
        console.log("    " + e.readableOutput);
        strings.push("    " + e.readableOutput + "\n");
    }

    // Print errors
    for (const error of disassemblyOutput.errors) {
        const prefix = error.severity === DISASM_WARNING ? "Warning" : "x";
        console.log(`[${prefix}] ${error.print()}`);
    }

    return strings;
}

module.exports = { disassemble, print };

/*
var o = "";

for (const e of elements) {
    const c = e.childNodes;
    const hex = "0x" + c[0].childNodes[0].getAttribute("id");
    let name = c[0].childNodes[0].getAttribute("name");
    let out;
    if (name) out = `t[${hex}] = ["${name}", 1, null];`;
    else out = `t[${hex}] = [null, 1, null];`;

    o += out;
}

*/

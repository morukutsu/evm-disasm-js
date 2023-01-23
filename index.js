/*
    evm-disasm-js
    - the goal is to write a fast disassembler with little/no dependencies
    - and decorate the code with helpers for common EVM bytecode structures
    - in the future, a decompiler could be included as well
*/

const { byteToHex } = require("./lib/string");
const c_evmOpcodesTable = require("./lib/opcodes");

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
*/
function disassemble(byteString) {
    if (typeof byteString !== "string")
        throw new Error("diassemble: byteString should be a string");

    if (!byteString.startsWith("0x"))
        throw new Error("disassemble: byteString should start with 0x");

    const bytes = Buffer.from(byteString.substr(2), "hex");

    const opcodes = [];
    const disassemblyErrors = [];
    const metadata = {};

    // Opcodes are indexed by the opcode index
    // Add a lookup table to index them by address
    let opcodesByAddr = {};

    // First pass: disassemble
    for (let i = 0; i < bytes.length; ) {
        const bytecode = bytes[i];
        const instructionData = c_evmOpcodesTable[bytecode];
        if (!instructionData)
            throw new Error(`No instruction ${bytecode.toString(16)}`);

        const [opcode, advance, fmt] = instructionData;
        let operandString = fmt ? fmt(bytes, i) : "";

        // TODO: Fix for when fmt() reaches the end of the disassembly, find a better fix
        if (operandString == "0x") operandString = "";

        const addr = i;

        i += advance;

        const readableOutput = `${addr.toString(16).toUpperCase()} ${
            opcode || byteToHex(bytecode).toUpperCase()
        } ${operandString}`;

        // Most instructions are one byte and take their operands from the stack
        // Except "PUSH" instructions which have another variable size constant
        let operandValue;
        if (opcode && opcode.startsWith("PUSH"))
            operandValue = BigInt(operandString);

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
    const jumpsByAddr = {};

    labels[0] = { name: "entry", addr: 0 };

    // We detect locations by looking at where JUMP & JUMPI instructions JUMP TO
    // We can combine this with a JUMPDEST analysis
    for (let i = 0; i < opcodes.length; i++) {
        const opcode = opcodes[i];
        const previousOpcode = opcodes[i - 1];

        if (
            previousOpcode &&
            (previousOpcode.opcode === "PUSH1" ||
                previousOpcode.opcode === "PUSH2") &&
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
                    data: {
                        dest: null,
                        addr: parseInt(previousOpcode.operandValue),
                    },
                });

                metadata.hasInvalidJumpDest = true;
            } else if (destinationOpcode.opcode !== "JUMPDEST") {
                addDisassemblyError(disassemblyErrors, {
                    code: "INVALID_JUMPDEST",
                    ...c_disassemblyErrors.INVALID_JUMPDEST,
                    data: {
                        dest: destinationOpcode.addr,
                        addr: parseInt(previousOpcode.operandValue),
                    },
                });

                metadata.hasInvalidJumpDest = true;
            } else {
                const name = `loc_${previousOpcode.operandValue.toString(16)}`;
                labels[previousOpcode.operandValue] = {
                    name,
                    addr: parseInt(previousOpcode.operandValue),
                    from: opcode.addr,
                };

                jumps.push({
                    addr: parseInt(previousOpcode.operandValue),
                    from: opcode.addr,
                    direct: opcode.opcode === "JUMP",
                });
            }
        }
    }

    for (const jump of jumps) {
        jumpsByAddr[jump.addr] = jump;
    }

    // Add all the other unlabelled JUMPDEST
    // VM is allowed to jump to these pieces of code, however it is more difficult to run a static analysis to know
    // from where code jumps on these labels
    for (let i = 0; i < opcodes.length; i++) {
        const opcode = opcodes[i];
        if (opcode.opcode === "JUMPDEST" && !labels[opcode.addr]) {
            const name = `loc_${opcode.addr.toString(16)}`;
            labels[opcode.addr] = {
                name,
                addr: opcode.addr,
                from: null,
            };
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
                hash: parseInt(opcode.operandValue),
                addr: parseInt(afterNext.operandValue),
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

    // Detect code sections
    // This algorithm is based on detecting free memory pointers and assuming
    // the first one is the deployment code and the second one the deployed contract code
    // By analyzing the code more deeply, we can be more precise on this analysis
    // Especially on manually written contracts or compiled differently
    // TODO:
    //  - detect CODECOPY + RETURN: it is a good hint that there is deployment code
    const codeSections = [];
    if (freeMemoryPointers.length === 2) {
        codeSections.push({
            start: freeMemoryPointers[0],
            end: freeMemoryPointers[1] - 1,
            name: "deploy",
        });

        codeSections.push({
            start: freeMemoryPointers[1],
            end: opcodes[opcodes.length - 1].addr,
            name: "deployed",
        });
    } else {
        codeSections.push({
            start: 0,
            end: opcodes[opcodes.length - 1].addr,
            name: "deployed",
        });
    }

    return {
        opcodes,
        labels,
        jumps,
        functions,
        errors: disassemblyErrors,
        codeSections,
        cache: {
            // optimization structures to access the disassembly content faster
            opcodesByAddr,
            jumpsByAddr,
        },
    };
}

function serialize(disassembly) {
    const opcodes = disassembly.opcodes.map((e) => ({
        ...e,
        operandValue:
            e.operandValue !== undefined && e.operandValue !== null
                ? e.operandValue.toString()
                : null,
    }));

    const errors = disassembly.errors.map((e) => ({
        ...e,
        print: undefined,
    }));

    return {
        opcodes,
        labels: disassembly.labels,
        jumps: disassembly.jumps,
        functions: disassembly.functions,
        errors,
        codeSections: disassembly.codeSections,
    };
}

function unserialize(serialized) {
    const opcodes = serialized.opcodes.map((e) => ({
        ...e,
        operandValue:
            e.operandValue !== undefined && e.operandValue !== null
                ? BigInt(e.operandValue)
                : null,
    }));

    const errors = [];
    for (const e of serialized.errors) {
        addDisassemblyError(errors, e);
    }

    return {
        opcodes,
        labels: serialized.labels,
        jumps: serialized.jumps,
        functions: serialized.functions,
        errors,
        codeSections: serialized.codeSections,
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

module.exports = {
    disassemble,
    print,
    serialize,
    unserialize,
    opcodesTable: c_evmOpcodesTable,
};

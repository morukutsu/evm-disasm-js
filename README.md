# evm-disasm-js

Ethereum VM (EVM) Bytecode disassembler.

The goals of this project are:

-   A fast EVM disassembler with little to no dependencies
-   Analysis of common byte code structures of the Solidity compiler
-   In the future, be the backend of a EVM Debugger and decompiler
-   Support new EVM EIPs

## Usage

At the moment, there is no npm package for this project. One will be published once the code will be more mature.

See `examples/` for more complete usage examples:

```javascript
const disassembler = require("./index");

const BYTECODE = "0x60806040";

const disassembly = disassembler.disassemble(BYTECODE);
console.log(disassembly);
```

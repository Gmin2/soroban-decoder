# @riverith/soroban-decompiler-wasm

Browser WASM build of the Soroban smart contract decompiler. Decompiles compiled Soroban `.wasm` files into readable Rust source code entirely client-side — no server required.

## Install

```bash
npm install @riverith/soroban-decompiler-wasm
```

## Quick Start

```js
import init, { decompile } from '@riverith/soroban-decompiler-wasm';

await init();

const response = await fetch('contract.wasm');
const bytes = new Uint8Array(await response.arrayBuffer());
const rustSource = decompile(bytes);
console.log(rustSource);
```

## API

### `decompile(wasm_bytes, signatures_only?)`

Decompile a Soroban WASM binary into Rust source code.

```js
const source = decompile(wasmBytes);           // full decompilation
const sigs = decompile(wasmBytes, true);        // types + signatures only (fast)
```

- **`wasm_bytes`** `Uint8Array` — raw WASM binary
- **`signatures_only`** `boolean?` — skip bytecode analysis, emit only type definitions and function stubs
- **Returns** `string` — formatted Rust source code

### `inspect(wasm_bytes)`

Extract the contract specification (types, functions, events, errors) as a string.

```js
const spec = inspect(wasmBytes);
```

### `imports(wasm_bytes)`

Resolve all WASM host function imports with their semantic Soroban names.

```js
const resolved = imports(wasmBytes);
```

### `score(original, decompiled)`

Score decompiled output accuracy against original source code. Returns JSON with type, signature, and body scores.

```js
const result = JSON.parse(score(originalRust, decompiledRust));
console.log(`accuracy: ${(result.overall * 100).toFixed(1)}%`);
```

### `benchmark(name, original, decompiled)`

Full benchmark report with per-function scores, statement alignments, and type comparisons.

```js
const report = JSON.parse(benchmark('my_contract', originalRust, decompiledRust));
```

## Usage with Stellar SDK

Fetch a deployed contract's WASM directly from the network and decompile it:

```js
import init, { decompile } from '@riverith/soroban-decompiler-wasm';
import { rpc } from '@stellar/stellar-sdk';

await init();

const server = new rpc.Server('https://soroban-testnet.stellar.org');
const contractId = 'CABC...XYZ';
const instance = await server.getContractData(contractId, 'instance');
// ... fetch WASM from ledger entry
const source = decompile(wasmBytes);
```

## Framework Examples

### React

```jsx
import { useState } from 'react';
import init, { decompile } from '@riverith/soroban-decompiler-wasm';

function Decompiler() {
  const [source, setSource] = useState('');

  async function handleFile(e) {
    await init();
    const buf = await e.target.files[0].arrayBuffer();
    setSource(decompile(new Uint8Array(buf)));
  }

  return (
    <div>
      <input type="file" accept=".wasm" onChange={handleFile} />
      <pre>{source}</pre>
    </div>
  );
}
```

### Vanilla JS

```html
<script type="module">
import init, { decompile } from '@riverith/soroban-decompiler-wasm';
await init();
window.decompile = decompile;
// Now use decompile(uint8Array) in the console
</script>
```

## Build from Source

```bash
# Requires wasm-pack
cargo install wasm-pack

# Build the package
wasm-pack build crates/soroban-decompiler-wasm --target web --release --scope riverith

# Output in crates/soroban-decompiler-wasm/pkg/
```

## Package Contents

| File | Description |
|------|-------------|
| `soroban_decompiler_wasm.js` | JS glue code with ESM exports |
| `soroban_decompiler_wasm.d.ts` | TypeScript type definitions |
| `soroban_decompiler_wasm_bg.wasm` | Compiled WASM binary (~2.5MB) |

## License

Apache-2.0

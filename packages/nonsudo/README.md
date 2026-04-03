# nonsudo

Mandate enforcement and cryptographic receipts for AI agents.

## Install

```bash
npm install nonsudo
```

## Usage

### Receipt API

```typescript
import { createReceipt, signReceipt, chainReceipt, verifyChain } from 'nonsudo';
```

### Policy engine

```typescript
import { loadPolicy, evaluatePolicy } from 'nonsudo/policy';
```

### OpenAI adapter

```typescript
import { createActionReceipt } from 'nonsudo/adapter-openai';
```

### LangChain adapter

```typescript
import { createNonSudoCallbacks } from 'nonsudo/adapter-langchain';

const llm = new ChatOpenAI({ callbacks: createNonSudoCallbacks(config) });
```

### Receipt store

```typescript
import { ReceiptStore } from 'nonsudo/store';
```

## CLI

```bash
nonsudo init                           # generate keypair + scaffold config
nonsudo observe                        # start observe proxy (local telemetry)
nonsudo verify receipts.ndjson         # L1 + L2 verification
nonsudo verify receipts.ndjson --full  # L1 + L2 + L3 + L4
nonsudo conform                        # conformance test vectors
nonsudo schemas list                   # list available schema packs
nonsudo keys list                      # list signing keypairs
nonsudo health                         # run diagnostic checks
nonsudo query --tool stripe_charge     # query the receipt store
nonsudo report --workflow-id <id>      # generate workflow report
nonsudo test receipts.ndjson           # replay chain against current policy
nonsudo watch                          # watch live receipt stream
nonsudo index receipts.ndjson          # index receipts into store
```

## Observe logs vs signed VAR receipts

`nonsudo observe` writes local observe logs for developer visibility.
These logs are not signed VAR receipts and are not a cryptographic
audit chain. They are lightweight telemetry for understanding what your
agent is doing during development.

For cryptographically signed, hash-chained, timestamped VAR receipts
suitable for compliance, audit, or regulatory use — see the
[NonSudo platform quickstart](https://nonsudo.com/docs/quickstart).

## For implementers

The `@varcore/*` packages are the underlying open standard implementation.
Any implementation conforming to the VAR-Core spec can reference them directly.
Full spec: https://github.com/nonsudo/varcore

## Links

- **Platform:** https://nonsudo.com/docs/quickstart
- **Schema registry:** https://schemas.nonsudo.com
- **License:** Apache-2.0

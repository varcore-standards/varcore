#!/usr/bin/env node
'use strict';

const pkg = require('../package.json');

console.log(`
nonsudo v${pkg.version}

Mandate enforcement and cryptographic receipts for AI agents.

Open source core (VAR-Core):
  npm install @varcore/core @varcore/receipts

Quick start:
  import { createReceipt, signReceipt, verifyChain } from '@varcore/receipts';

Full platform (proxy + policy engine + dashboard):
  https://nonsudo.com/docs/quickstart

Schema registry:
  https://schemas.nonsudo.com

GitHub:
  https://github.com/nonsudo/varcore
`);
process.exit(0);

# ClawGuard References

## Key Repos to Reference

### Prompt Injection Detection

**protectai/rebuff** (1,415 ⭐)
https://github.com/protectai/rebuff

Multi-layer defense:
- Heuristics filter
- LLM-based detection
- VectorDB for similar attacks
- Canary tokens for leak detection

Can adapt: Heuristic patterns, detection strategies

---

**lakeraai/pint-benchmark** (158 ⭐)
https://github.com/lakeraai/pint-benchmark

Benchmark for prompt injection detectors. 
Use: Test cases for our prompt analyzer.

---

### Supply Chain / npm Security

**ParisNeo/npm-security-scanner** (4 ⭐)
https://github.com/ParisNeo/npm-security-scanner

Built after the Sept 2025 npm attack. Detects:
- Crypto wallet targeting (window.ethereum, MetaMask)
- Obfuscation (_0x patterns with threshold logic)
- Malware function names (checkethereumw, runmask, newdlocal)
- Network interception (XMLHttpRequest.prototype, fetch hijacking)
- Suspicious scripts (eval, base64, curl|bash)
- Known malicious package hashes

Can use: Pattern lists, threshold logic for obfuscation.

---

### Typosquatting Detection

**elceef/dnstwist** (5,572 ⭐)
https://github.com/elceef/dnstwist

Domain permutation engine. Generates typo variants:
- Character omission
- Character swap
- Adjacent key typos
- Homoglyphs
- Insertion/deletion

Adapt algo for package name typosquatting.

**typogenerator** (86 ⭐)
https://github.com/rangertaha/typogenerator

Golang typosquatting generator. 

---

### Other Useful

**pytector** (36 ⭐)
https://github.com/MaxMLang/pytector

Python prompt injection detector. Simple patterns.

**agentic-ai-security-starter-kit** (7 ⭐)
https://github.com/Aembit/agentic-ai-security-starter-kit

Claude Code hooks, sandbox configs. Recent.

---

## Patterns to Incorporate

### From npm-security-scanner
```javascript
// Crypto targeting
/window\.ethereum/
/metamask/i
/web3\.eth/

// Obfuscation
/_0x[a-f0-9]{4,}/g  // with threshold
/\\x[0-9a-f]{2}/g
/\\u[0-9a-f]{4}/g

// Malware functions
/checkethereumw/
/runmask/
/newdlocal/

// Network interception  
/XMLHttpRequest\.prototype/
/fetch\s*=\s*function/
```

### From rebuff (prompt injection)
```
- "ignore previous instructions"
- "disregard above"
- "new instructions:"
- "system prompt:"
- "you are now"
- Canary word detection
```

### Typosquat Techniques (dnstwist)
```
Original: lodash
Variants:
- lodas (omission)
- lodahs (swap)
- lodash1 (addition)
- l0dash (homoglyph)
- lodaash (repeat)
- lodsh (vowel drop)
```

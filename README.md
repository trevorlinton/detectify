# Detectify

This is a node.js module for running a scan on a hostname via www.detectify.com enterprise API.  The result is a JSON scan full report. 

## Usage

Must have `DETECTIFY_TOKEN` and `DETECTIFY_SECRET_TOKEN` in environment.

```
const detectify = require ('./detectify.js')
console.log(await detectify.scan_domain('www.example.com'))
```

Note that the domain passed in can be any host that is a sub-domain of an already verified host setup in detectify, this will fail if ran on hosts not verified.

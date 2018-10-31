# Owasp to CVSS 
> A tool to calculate the CVSS from the OWASP description of a vulnerability  

## Requirements

[here](./REQUIREMENTS.md)

## Usage

At the top of [./files/owasptocvss.js](./files/owasptocvss.js) you can configure the calculation of bounty amount :   

```javascript
// min bounty amount 
var b_min = 50;
// max bounty amount 
var b_max = 10000;
// internal parameter
var n = 1;
// max cvss
var Cvss_max = 10;
```

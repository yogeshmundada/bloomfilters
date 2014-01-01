var fs = require("fs");

var fname = process.argv[2];
var stats = fs.statSync(fname);

var buffer = new Buffer(stats.size);
fd = fs.openSync(fname, "r");

fs.readSync(fd, buffer, 0, buffer.length, null);
fs.closeSync(fd);

var base64_fname = fname.split(".")[0] + ".base64";
var buf_base64 = buffer.toString('base64');

fs.writeFileSync(base64_fname, buf_base64);



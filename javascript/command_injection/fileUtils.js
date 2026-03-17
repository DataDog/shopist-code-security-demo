const { exec, execSync } = require('child_process');

// VULN 1: exec with string concatenation - file format conversion
function convertFileFormat(inputFile, outputFormat) {
    exec('convert ' + inputFile + ' output.' + outputFormat, (err, stdout) => {
        if (err) throw err;
        return stdout;
    });
}

// VULN 2: execSync with template literal - create zip archive
function createArchive(directory, archiveName) {
    return execSync(`zip -r ${archiveName}.zip ${directory}`).toString();
}

// VULN 3: exec with string concatenation - set file permissions
function setFilePermissions(filepath, permissions) {
    exec('chmod ' + permissions + ' ' + filepath, (err) => {
        if (err) throw err;
    });
}

module.exports = { convertFileFormat, createArchive, setFilePermissions };

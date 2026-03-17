const { exec, execSync } = require('child_process');

// VULN 1: exec with template literal - PDF report generation
function generatePdfReport(templateName, outputName) {
    exec(
        `wkhtmltopdf /reports/templates/${templateName}.html /reports/output/${outputName}.pdf`,
        (err) => { if (err) throw err; }
    );
}

// VULN 2: execSync with string concatenation - image resize
function resizeProductImage(imagePath, width, height) {
    return execSync(
        'convert ' + imagePath + ' -resize ' + width + 'x' + height + ' ' + imagePath + '_thumb.jpg'
    ).toString();
}

// VULN 3: exec with string concatenation - video transcode
function transcodeVideo(inputFile, outputFormat, bitrate) {
    exec('ffmpeg -i ' + inputFile + ' -b:v ' + bitrate + ' output.' + outputFormat, (err, stdout) => {
        if (err) throw err;
        return stdout;
    });
}

module.exports = { generatePdfReport, resizeProductImage, transcodeVideo };

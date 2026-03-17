package commandinjection

import (
	"fmt"
	"os/exec"
)

// VULN 1: exec.Command sh -c with string concatenation - PDF generation
func GeneratePDFReport(templateName, outputName string) ([]byte, error) {
	cmdStr := "wkhtmltopdf /reports/templates/" + templateName + ".html /reports/output/" + outputName + ".pdf"
	cmd := exec.Command("sh", "-c", cmdStr)
	return cmd.Output()
}

// VULN 2: exec.Command sh -c with fmt.Sprintf - image resize
func ResizeProductImage(imagePath string, width, height int) ([]byte, error) {
	cmdStr := fmt.Sprintf("convert %s -resize %dx%d %s_resized.jpg", imagePath, width, height, imagePath)
	cmd := exec.Command("sh", "-c", cmdStr)
	return cmd.Output()
}

// VULN 3: exec.Command sh -c with string concatenation - ffmpeg transcode
func TranscodeVideo(inputFile, outputFormat, bitrate string) ([]byte, error) {
	cmd := exec.Command("sh", "-c", "ffmpeg -i "+inputFile+" -b:v "+bitrate+" output."+outputFormat)
	return cmd.Output()
}

package commandinjection

import (
	"fmt"
	"os/exec"
)

// VULN 1: exec.Command sh -c with string concatenation - file conversion
func ConvertFileFormat(inputFile, outputFormat string) ([]byte, error) {
	cmd := exec.Command("sh", "-c", "convert "+inputFile+" output."+outputFormat)
	return cmd.Output()
}

// VULN 2: exec.Command sh -c with fmt.Sprintf - create zip archive
func CreateArchive(directory, archiveName string) ([]byte, error) {
	cmdStr := fmt.Sprintf("zip -r %s.zip %s", archiveName, directory)
	cmd := exec.Command("sh", "-c", cmdStr)
	return cmd.Output()
}

// VULN 3: exec.Command sh -c with string concatenation - chmod
func SetFilePermissions(filepath, permissions string) ([]byte, error) {
	cmd := exec.Command("sh", "-c", "chmod "+permissions+" "+filepath)
	return cmd.Output()
}

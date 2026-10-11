//go:build !onnx

package contextmodel

import (
	"fmt"
	"io"
)

func Serve(_ string, _ string, _ string, _ io.Reader, out io.Writer) error {
	_, err := fmt.Fprintln(out, `{"error":"contextual inference requires an onnx build"}`)
	return err
}

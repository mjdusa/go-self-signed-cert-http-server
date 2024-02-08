package file

import (
	"fmt"
	"io"
	"os"
)

func CopyFile(dstName, srcName string) (int64, error) {
	src, err := os.Open(srcName)
	if err != nil {
		return 0, fmt.Errorf("failed Open: %w", err)
	}
	defer src.Close()

	dst, err := os.Create(dstName)
	if err != nil {
		return 0, fmt.Errorf("failed Create: %w", err)
	}
	defer dst.Close()

	wrote, err := io.Copy(dst, src)
	if err != nil {
		return 0, fmt.Errorf("failed Copy: %w", err)
	}

	return wrote, nil
}

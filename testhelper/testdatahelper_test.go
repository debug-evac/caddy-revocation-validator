package testhelper

import (
	"fmt"
	"path"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetTestDataFilePath(t *testing.T) {
	result := GetTestDataFilePath("crl1")
	_, curPath, _, ok := runtime.Caller(0)
	if !ok {
		panic(fmt.Errorf("could not find current working directory"))
	}
	curPath = path.Join(curPath, "../../")
	resultRelative, err := filepath.Rel(curPath, result)
	assert.NoError(t, err)
	resultRelative = filepath.ToSlash(resultRelative)
	assert.Equal(t, "testdata/crl1", resultRelative)
}

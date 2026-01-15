package hashing

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSum64(t *testing.T) {
	result := Sum64("helloworld")
	expectedResult := []byte{129, 85, 74, 146, 94, 49, 217, 16}
	assert.Equal(t, expectedResult, result, "fnva hash result does not match")
}

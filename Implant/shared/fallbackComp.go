//go:build !withComp

package shared

import "bytes"

func DoComp(data string) (bytes.Buffer, bool) {
	tossAway := bytes.NewBufferString(data)
	return *tossAway, false

}

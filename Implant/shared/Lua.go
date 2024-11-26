//go:build withLua

package shared

import (
	"fmt"

	lua "github.com/yuin/gopher-lua"
)

func DoLua(LuaStr string) bool {
	L := lua.NewState()
	L.OpenLibs()
	defer L.Close()
	if err := L.DoString(LuaStr); err != nil {
		fmt.Println(err.Error())
		return false
	}
	return true
}

package shared

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
)

func GetCurrentDir() (mydir string) {
	mydir, err := os.Getwd()
	if err != nil {
		mydir = "error getting dir"
	}
	fmt.Println(mydir)
	return mydir
}

func GetCurrentUser() (name string) {
	userName, err := user.Current()
	if err != nil {
		name = "error getting username"
	}
	if userName != nil {
		name = userName.Username
	}
	return name
}

func GetGroupsSID() (groups string) {
	vars, err := os.Getgroups()
	if err != nil {
		groups = "error getting group info %e" + err.Error()
	}
	strAr := make([]string, len(vars))
	for i, num := range vars {
		strAr[i] = strconv.Itoa(num)
	}
	groups = strings.Join(strAr, ",")
	return groups
}

func ReadFile(filePath string) (fileOut string) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		fileOut = "error reading file %e" + err.Error()
	}
	fileOut = string(content)
	return fileOut
}

package main

import (
	"fmt"
	"io/ioutil"
)

func main() {
	//out, err := crypt.Encrypt(1, []byte("hello"), []byte("{}"))
	out, err := ioutil.ReadFile("/home/aaron/code/kniopass/hello.kniopass")
	fmt.Println(err)
	for i, x := range out {
		if i%17 == 0 && i != 0 {
			fmt.Println()
		}
		fmt.Printf("\\x%02x", x)
	}
	fmt.Println("")
}

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
)

const filename = "e:license.dat"

func main() {
	license := readFile()
	fmt.Println("读取到的密文：", license)
	plaintext := decode(license)
	format(plaintext)
}

func PKCS5Unpadding(encrypt []byte) []byte {
	padding := encrypt[len(encrypt)-1]
	return encrypt[:len(encrypt)-int(padding)]
}

// 解密
func decode(license string) string {
	license_arr := strings.Split(license, "")
	index := license_arr[0:1]
	perfix_len, _ := strconv.Atoi(index[0])
	suffix_len := len(license_arr) - (32 - perfix_len)
	ciphertext_arr := license_arr[1+perfix_len : suffix_len]
	ciphertext_str := strings.Join(ciphertext_arr, "")
	fmt.Println("分析出密文：", ciphertext_str)
	fmt.Println("开始解码")

	salt := []byte("hsck")
	password := []byte("hsckhsckhsckhsckhsckhsckhsckhsck")
	key := pbkdf2.Key(password, salt, 2333, 32, sha256.New)

	ciphertext, _ := hex.DecodeString(ciphertext_str)
	fmt.Printf("分析出密文：%x", ciphertext)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	// CBC mode always works in whole blocks.
	if len(ciphertext)%aes.BlockSize != 0 {
		panic("ciphertext is not a multiple of the block size")
	}
	mode := cipher.NewCFBDecrypter(block, iv)
	mode.XORKeyStream(ciphertext, ciphertext)
	fmt.Printf("\r\n解析出字符串：%s\n", ciphertext)
	return string(ciphertext)
}

// 格式化加密内容
func format(plaintext string) {
	// 去除占位符（*）
	plaintext = string(PKCS5Unpadding([]byte(plaintext)))
	plaintext_arr := strings.Split(plaintext, "|")
	// fmt.Println(plaintext_arr)
	// plaintext_map := make(map[string]interface{})
	fmt.Println("UUID：\t\t", plaintext_arr[0])
	fmt.Println("使用时长(天)：\t", plaintext_arr[1])
	fmt.Println("设备数量：\t\t", plaintext_arr[2])
	fmt.Println("使用日期：\t\t", plaintext_arr[3])
}

// 读取文件
func readFile() string {
	var err1 error
	/***************************** 第一种方式: 使用 io.WriteString 写入文件 ***********************************************/
	if checkFileIsExist(filename) { //如果文件存在
		_, err1 = os.OpenFile(filename, os.O_APPEND, 0666) //打开文件
	} else {
		panic("文件不存在")
	}
	if err1 != nil {
		panic(err1)
	}

	buff := make([]byte, 1024)

	buff, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Println(err)
	}
	return string(buff)
}
func checkFileIsExist(filename string) bool {
	var exist = true
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		exist = false
	}
	return exist
}

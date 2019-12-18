package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"io"
	math_rand "math/rand"
	"os"
	"strconv"
	"strings"
	"time"
)

const TOKEN = "123456"

func main() {
	fmt.Println("加密程序")

	check_token()

	fmt.Println("-------->获取并解析参数")
	var UUID string
	var use_duration int
	var device_limit int
	var auth_date string
	flag.StringVar(&UUID, "UUID", "", "机器码")
	flag.IntVar(&use_duration, "duration", 10, "授权时长")
	flag.IntVar(&device_limit, "device", 100, "设备数")
	flag.StringVar(&auth_date, "auth_date", "1997-01-01", "授权日期")
	flag.Parse()
	fmt.Printf("机器码：%s\n授权时长：%d天\n设备数量：%d台\n授权时间：%s \r\n", UUID, use_duration, device_limit, auth_date)

	continues := "Y"
	fmt.Printf("请确认生成许可授权信息,任意键继续,退出（N）：")
	fmt.Scanln(&continues)
	if strings.ToUpper(continues) == "N" {
		return
	}

	origin_content := strings.Join([]string{UUID, strconv.Itoa(use_duration), strconv.Itoa(device_limit), auth_date}, "|")
	fmt.Println("原始字符串：", origin_content)

	ciphertext := encrypt(origin_content)
	ciphertext_str := hex.EncodeToString(ciphertext)
	license := mingle(ciphertext_str)
	writeFile(license)

	now := time.Now().Format("2006-01-02")
	fmt.Printf("当前日期：%s \r\n", now)
}

// 扰乱授权码
func mingle(ciphertext string) string {
	// 生成md5
	h := md5.New()
	io.WriteString(h, "hsck")
	md5_code := h.Sum(nil)
	fmt.Printf("md5 %x\n", md5_code)

	// 生成随机数
	math_rand.Seed(time.Now().Unix())
	random := math_rand.Intn(10)
	fmt.Println("random", random)
	md5_code_arr := strings.Split(hex.EncodeToString(md5_code), "")
	md5_code_prefix := md5_code_arr[0:random]
	md5_code_suffix := md5_code_arr[random:]
	license := strings.Join([]string{strconv.Itoa(random), strings.Join(md5_code_prefix, ""), ciphertext, strings.Join(md5_code_suffix, "")}, "")
	fmt.Println("license", license)
	return license
}

// 检查口令
func check_token() bool {
	fmt.Printf("请输入口令：")
	for {
		var token string
		fmt.Scanln(&token)
		if token != TOKEN {
			fmt.Printf("口令不正确, 请重新输入：")
			continue
		}
		return true
	}
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

// 加密
func encrypt(origin_content string) []uint8 {
	fmt.Println("\r\n开始加密")

	// key := []byte("hsckhsckhsckhsck")
	salt := []byte("hsck")
	password := []byte("hsckhsckhsckhsckhsckhsckhsckhsck")
	key := pbkdf2.Key(password, salt, 2333, 32, sha256.New)
	plaintext := []byte(origin_content)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	origin_content_byte := PKCS5Padding(plaintext, block.BlockSize())
	plaintext = origin_content_byte
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	mode := cipher.NewCFBEncrypter(block, iv)
	mode.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	fmt.Printf("生成密文：%x\r\n", ciphertext)
	return ciphertext
}

// 写入文件
func writeFile(ciphertext string) {
	wireteString := ciphertext
	fmt.Println("最终密文：", wireteString)
	fmt.Println("开始写文件")

	var filename = "./license.dat"
	var f *os.File
	var err1 error
	/***************************** 第一种方式: 使用 io.WriteString 写入文件 ***********************************************/
	if checkFileIsExist(filename) { //如果文件存在
		f, err1 = os.OpenFile(filename, os.O_APPEND, 0666) //打开文件
		f, err1 = os.Create(filename)                      //创建文件
		fmt.Println("文件存在")
	} else {
		f, err1 = os.Create(filename) //创建文件
		fmt.Println("文件不存在")
	}
	if err1 != nil {
		panic(err1)
	}
	n, err1 := io.WriteString(f, wireteString) //写入文件(字符串)

	if err1 != nil {
		panic(err1)
	}
	fmt.Printf("写入 %d 个字节n", n)
}
func checkFileIsExist(filename string) bool {
	var exist = true
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		exist = false
	}
	return exist
}

package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"unsafe"
)

const PLAIN_FILE_OPEN_ERROR = -1
const KEY_FILE_OPEN_ERROR = -2
const CIPHER_FILE_OPEN_ERROR = -3
const OK = 1
const PARAM_ERROR = -1

/*初始置换表IP*/
var IP_Table = []int{57, 49, 41, 33, 25, 17, 9, 1,
	59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5,
	63, 55, 47, 39, 31, 23, 15, 7,
	56, 48, 40, 32, 24, 16, 8, 0,
	58, 50, 42, 34, 26, 18, 10, 2,
	60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6}

/*逆初始置换表IP^-1*/
var IP_1_Table = []int{39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30,
	37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28,
	35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26,
	33, 1, 41, 9, 49, 17, 57, 25,
	32, 0, 40, 8, 48, 16, 56, 24}

/*扩充置换表E*/
var E_Table = []int{31, 0, 1, 2, 3, 4,
	3, 4, 5, 6, 7, 8,
	7, 8, 9, 10, 11, 12,
	11, 12, 13, 14, 15, 16,
	15, 16, 17, 18, 19, 20,
	19, 20, 21, 22, 23, 24,
	23, 24, 25, 26, 27, 28,
	27, 28, 29, 30, 31, 0}

/*置换函数P*/
var P_Table = []int{15, 6, 19, 20, 28, 11, 27, 16,
	0, 14, 22, 25, 4, 17, 30, 9,
	1, 7, 23, 13, 31, 26, 2, 8,
	18, 12, 29, 5, 21, 10, 3, 24}

/*S盒*/
var S =
/*S1*/
[][][]int{{{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
	{0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
	{4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
	{15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}},
	/*S2*/
	{{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
		{3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
		{0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
		{13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}},
	/*S3*/
	{{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
		{13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
		{13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
		{1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}},
	/*S4*/
	{{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
		{13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
		{10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
		{3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}},
	/*S5*/
	{{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
		{14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
		{4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
		{11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}},
	/*S6*/
	{{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
		{10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
		{9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
		{4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}},
	/*S7*/
	{{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
		{13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
		{1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
		{6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}},
	/*S8*/
	{{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
		{1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
		{7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
		{2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}}}

/*置换选择1*/
var PC_1 = []int{56, 48, 40, 32, 24, 16, 8,
	0, 57, 49, 41, 33, 25, 17,
	9, 1, 58, 50, 42, 34, 26,
	18, 10, 2, 59, 51, 43, 35,
	62, 54, 46, 38, 30, 22, 14,
	6, 61, 53, 45, 37, 29, 21,
	13, 5, 60, 52, 44, 36, 28,
	20, 12, 4, 27, 19, 11, 3}

/*置换选择2*/
var PC_2 = []int{13, 16, 10, 23, 0, 4, 2, 27,
	14, 5, 20, 9, 22, 18, 11, 3,
	25, 7, 15, 6, 26, 19, 12, 1,
	40, 51, 30, 36, 46, 54, 29, 39,
	50, 44, 32, 46, 43, 48, 38, 55,
	33, 52, 45, 41, 49, 35, 28, 31}

/*对左移次数的规定*/
var MOVE_TIMES = []int{1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1}

// func main() {
// 	var des DES
// 	// plaintxt := "this is a test!"
// 	// dec := des.EncryptText(plaintxt, "ArcVideo")
// 	// fmt.Println(string(dec))
// 	// enc := des.DecryptText(string(dec), "ArcVideo")
// 	// fmt.Println(string(enc))

// 	des.EncryptFile("./image/1004.jpg", "./image/1004.jpg_aes", "ArcVideo")
// 	des.DecryptFile("./image/1004.jpg_aes", "./image/1004_1.jpg", "ArcVideo")
// }

func memset(s unsafe.Pointer, c byte, n uintptr, start_index uintptr) {
	ptr := uintptr(s)
	var i uintptr
	for i = 0; i < n; i++ {
		len := start_index + i
		pByte := (*byte)(unsafe.Pointer(ptr + len))
		*pByte = c
	}
}

func memcpy(source []int32, data []int32, count int, len int) {
	copy(source[len:], data[0:count])
}

type DES struct {
}

func (d DES) ByteToBit(ch int32, bit [8]int32) [8]int32 {
	cnt := 0
	for cnt = 0; cnt < 8; cnt++ {
		bit[cnt] = ch >> cnt & 1
	}
	return bit
}

func (d DES) BitToByte(bit [8]int32, ch int32) string {
	cnt := 0
	for cnt = 0; cnt < 8; cnt++ {
		ch |= bit[cnt] << cnt
	}
	return string(ch)
}

func (d DES) Char8ToBit64(ch [8]int32, bit [64]int32) [64]int32 {
	cnt := 0
	for cnt = 0; cnt < 8; cnt++ {
		var tch int32
		tch = ch[cnt]
		var tbit [8]int32
		copy(tbit[0:], bit[cnt*8:(cnt+1)*8])
		a := d.ByteToBit(tch, tbit)
		copy(bit[cnt*8:(cnt+1)*8], a[0:])
	}
	return bit
}

func (d DES) Bit64ToChar8(bit [64]int32, ch [8]int32) [8]int32 {
	cnt := 0
	for cnt = 0; cnt < 8; cnt++ {
		var tbit [8]int32
		copy(tbit[0:], bit[cnt*8:8*(cnt+1)])
		result := d.BitToByte(tbit, 0)
		r_result := []rune(result)
		copy(ch[cnt*1:(cnt+1)*1], r_result[0:])
	}
	return ch
}

func (d DES) DES_MakeSubKeys(key [64]int32, subKeys [16][48]int32) [16][48]int32 {
	var temp [56]int32
	cnt := 0
	temp = d.DES_PC1_Transform(key, temp)

	for cnt = 0; cnt < 16; cnt++ { /*16轮跌代，产生16个子密钥*/
		temp = d.DES_ROL(temp, MOVE_TIMES[cnt])                /*循环左移*/
		subKeys[cnt] = d.DES_PC2_Transform(temp, subKeys[cnt]) /*PC2置换，产生子密钥*/
	}
	return subKeys
}

func (d DES) DES_PC1_Transform(key [64]int32, tempbts [56]int32) [56]int32 {
	cnt := 0
	for cnt = 0; cnt < 56; cnt++ {
		tempbts[cnt] = key[PC_1[cnt]]
	}
	return tempbts
}

func (d DES) DES_PC2_Transform(key [56]int32, tempbts [48]int32) [48]int32 {
	cnt := 0
	for cnt = 0; cnt < 48; cnt++ {
		tempbts[cnt] = key[PC_2[cnt]]
	}
	return tempbts
}

func (d DES) DES_ROL(data [56]int32, time int) [56]int32 {
	var temp [56]int32
	/*保存将要循环移动到右边的位*/
	copy(temp[0:time], data[0:time])
	copy(temp[time:2*time], data[28:28+time])

	/*前28位移动*/
	copy(data[0:28], data[time:28])
	copy(data[28-time:28], temp[0:time])

	/*后28位移动*/
	copy(data[28:56-time], data[28+time:])
	copy(data[56-time:], temp[time:2*time])
	return data
}

func (d DES) DES_IP_Transform(data [64]int32) [64]int32 {
	cnt := 0
	var temp [64]int32
	for cnt = 0; cnt < 64; cnt++ {
		temp[cnt] = data[IP_Table[cnt]]
	}
	data = temp
	return data
}

func (d DES) DES_IP_1_Transform(data [64]int32) [64]int32 {
	cnt := 0
	var temp [64]int32
	for cnt = 0; cnt < 64; cnt++ {
		temp[cnt] = data[IP_1_Table[cnt]]
	}
	data = temp
	return data
}

func (d DES) DES_E_Transform(data [48]int32) [48]int32 {
	cnt := 0
	var temp [48]int32
	for cnt = 0; cnt < 48; cnt++ {
		temp[cnt] = data[E_Table[cnt]]
	}
	data = temp
	return data
}

func (d DES) DES_P_Transform(data [32]int32) [32]int32 {
	cnt := 0
	var temp [32]int32
	for cnt = 0; cnt < 32; cnt++ {
		temp[cnt] = data[P_Table[cnt]]
	}
	copy(data[0:], temp[0:])
	return data
}

func (d DES) DES_XOR(R [48]int32, L [48]int32, count int) [48]int32 {
	cnt := 0
	for cnt = 0; cnt < count; cnt++ {
		R[cnt] ^= L[cnt]
	}
	return R
}

func (d DES) DES_SBOX(data [48]int32) [48]int32 {
	cnt := 0
	var line int32
	var row int32
	var output int32
	cur1 := 0
	cur2 := 0
	for cnt = 0; cnt < 8; cnt++ {
		cur1 = cnt * 6
		cur2 = cnt << 2

		/*计算在S盒中的行与列*/
		line = (data[cur1] << 1) + data[cur1+5]
		row = (data[cur1+1] << 3) + (data[cur1+2] << 2) + (data[cur1+3] << 1) + data[cur1+4]
		output = int32(S[cnt][line][row])

		/*化为2进制*/
		data[cur2] = (output & 0X08) >> 3
		data[cur2+1] = (output & 0X04) >> 2
		data[cur2+2] = (output & 0X02) >> 1
		data[cur2+3] = output & 0x01
	}
	return data
}

func (d DES) DES_Swap(left [32]int32, right [32]int32) [64]int32 {
	var temp [64]int32
	copy(temp[0:32], right[0:])
	copy(temp[32:], left[0:])
	return temp
}

func (d DES) DES_EncryptBlock(plainBlock [8]int32, subKeys [16][48]int32, cipherBlock [8]int32) [8]int32 {
	var plainBits [64]int32
	var copyRight [48]int32
	cnt := 0

	plainBits = d.Char8ToBit64(plainBlock, plainBits)
	/*初始置换（IP置换）*/

	plainBits = d.DES_IP_Transform(plainBits)

	/*16轮迭代*/
	for cnt = 0; cnt < 16; cnt++ {
		copy(copyRight[:32], plainBits[32:])

		/*将右半部分进行扩展置换，从32位扩展到48位*/
		copyRight = d.DES_E_Transform(copyRight)

		/*将右半部分与子密钥进行异或操作*/
		copyRight = d.DES_XOR(copyRight, subKeys[cnt], 48)

		/*异或结果进入S盒，输出32位结果*/
		copyRight = d.DES_SBOX(copyRight)

		/*P置换*/
		var copyRight_t [32]int32
		copy(copyRight_t[:], copyRight[0:32])
		r := d.DES_P_Transform(copyRight_t)
		copy(copyRight[0:32], r[0:])

		/*将明文左半部分与右半部分进行异或*/
		var plainBits_t [48]int32
		copy(plainBits_t[:], plainBits[:48])
		r1 := d.DES_XOR(plainBits_t, copyRight, 32)
		copy(plainBits[:48], r1[:])

		if cnt != 15 {
			/*最终完成左右部的交换*/
			var plainBits_left [32]int32
			var plainBits_right [32]int32
			copy(plainBits_left[:], plainBits[0:32])
			copy(plainBits_right[:], plainBits[32:])
			plainBits = d.DES_Swap(plainBits_left, plainBits_right)
		}
	}

	/*逆初始置换（IP^1置换）*/
	plainBits = d.DES_IP_1_Transform(plainBits)

	cipherBlock = d.Bit64ToChar8(plainBits, cipherBlock)
	return cipherBlock
}

func (d DES) DES_DecryptBlock(cipherBlock [8]int32, subKeys [16][48]int32, plainBlock [8]int32) [8]int32 {
	var cipherBits [64]int32
	var copyRight [48]int32
	cnt := 0

	cipherBits = d.Char8ToBit64(cipherBlock, cipherBits)
	/*初始置换（IP置换）*/
	cipherBits = d.DES_IP_Transform(cipherBits)

	/*16轮迭代*/
	for cnt = 15; cnt >= 0; cnt-- {
		copy(copyRight[0:32], cipherBits[32:])

		/*将右半部分进行扩展置换，从32位扩展到48位*/
		copyRight = d.DES_E_Transform(copyRight)

		/*将右半部分与子密钥进行异或操作*/
		copyRight = d.DES_XOR(copyRight, subKeys[cnt], 48)

		/*异或结果进入S盒，输出32位结果*/
		copyRight = d.DES_SBOX(copyRight)
		/*P置换*/
		var copyRight_t [32]int32
		copy(copyRight_t[:], copyRight[:32])
		r := d.DES_P_Transform(copyRight_t)
		copy(copyRight[0:32], r[:])

		/*将明文左半部分与右半部分进行异或*/
		var cipherBits_t [48]int32
		copy(cipherBits_t[:], cipherBits[:48])
		r1 := d.DES_XOR(cipherBits_t, copyRight, 32)
		copy(cipherBits[:48], r1[:])

		if cnt != 0 {
			/*最终完成左右部的交换*/
			var cipherBits_left [32]int32
			var cipherBits_right [32]int32
			copy(cipherBits_left[:], cipherBits[0:32])
			copy(cipherBits_right[:], cipherBits[32:])
			cipherBits = d.DES_Swap(cipherBits_left, cipherBits_right)
		}
	}
	/*逆初始置换（IP^1置换）*/
	cipherBits = d.DES_IP_1_Transform(cipherBits)

	plainBlock = d.Bit64ToChar8(cipherBits, plainBlock)
	return plainBlock
}

func (d DES) EncryptText(pszInText_str string, cszpKey_str string) []rune {
	pszInText := []rune(pszInText_str)
	cszpKey := []rune(cszpKey_str)

	count := 0
	var plainBlock [8]int32
	var cipherBlock [8]int32
	var keyBlock [8]int32
	var bKey [64]int32
	var subKeys [16][48]int32

	var pchData = pszInText
	// fmt.Println(pchData)

	/*设置密钥*/
	copy(keyBlock[:8], cszpKey[:8])

	/*将密钥转换为二进制流*/
	bKey = d.Char8ToBit64(keyBlock, bKey)
	/*生成子密钥*/
	subKeys = d.DES_MakeSubKeys(bKey, subKeys)

	var strData []int32
	pch := pchData
	pch_index := 0

	for {
		plainBlock = [8]int32{0, 0, 0, 0, 0, 0, 0, 0}
		pch_last := pch_index + 8
		if pch_last > len(pch) {
			pch_last = len(pch)
		}
		tmp := pch[pch_index:pch_last]
		nLen := len(tmp)
		copy(plainBlock[:8], tmp)
		if nLen < 8 {
			count = nLen
			break
		} else {
			cipherBlock = d.DES_EncryptBlock(plainBlock, subKeys, cipherBlock)
			for _, t := range cipherBlock {
				strData = append(strData, t)
			}
			pch_index += 8
		}
	}

	if count > 0 {
		/*填充*/
		// fmt.Println(plainBlock)
		// memset(unsafe.Pointer(&plainBlock), 0, uintptr(7-count), uintptr(count))
		// var wait_zero [8]int32
		// copy(plainBlock[count:], wait_zero[:7-count])

		/*最后一个字符保存包括最后一个字符在内的所填充的字符数量*/
		plainBlock[7] = int32(8 - count)

		cipherBlock = d.DES_EncryptBlock(plainBlock, subKeys, cipherBlock)
		for _, t := range cipherBlock {
			strData = append(strData, t)
		}
	}
	return strData
}

func (d DES) DecryptText(pszInText_str string, cszpKey_str string) []rune {
	pszInText := []rune(pszInText_str)
	cszpKey := []rune(cszpKey_str)
	fmt.Println("加密码")
	for i := 0; i < 16; i++ {
		fmt.Printf("%x ", pszInText[i])
	}
	fmt.Printf("\n")

	var count int32
	times := 0
	var plainBlock [8]int32
	var cipherBlock [8]int32
	var keyBlock [8]int32
	var bKey [64]int32
	var subKeys [16][48]int32

	nSize := len(pszInText)
	var pchData = pszInText

	/*设置密钥*/
	copy(keyBlock[:8], cszpKey[:8])

	/*将密钥转换为二进制流*/
	bKey = d.Char8ToBit64(keyBlock, bKey)
	/*生成子密钥*/
	subKeys = d.DES_MakeSubKeys(bKey, subKeys)

	var strData []int32
	pch := pchData
	pch_index := 0

	for {
		/*密文的字节数一定是8的整数倍*/
		cipherBlock = [8]int32{0, 0, 0, 0, 0, 0, 0, 0}
		plainBlock = [8]int32{0, 0, 0, 0, 0, 0, 0, 0}

		pch_last := pch_index + 8
		if pch_last > len(pch) {
			pch_last = len(pch)
		}
		tmp := pch[pch_index:pch_last]
		copy(cipherBlock[:8], tmp)
		plainBlock = d.DES_DecryptBlock(cipherBlock, subKeys, plainBlock)
		times += 8
		pch_index += 8
		if times < nSize {
			for _, t := range plainBlock {
				strData = append(strData, t)
			}
		} else {
			break
		}
	}

	/*判断末尾是否被填充*/
	if plainBlock[7] < 8 {
		count = 8 - plainBlock[7]
		for {
			t := plainBlock[count]
			if t != 0 {
				break
			}
			count++
			if count < 7 {
				break
			}
		}
	}
	cipherBlock = [8]int32{0, 0, 0, 0, 0, 0, 0, 0}
	if count == 7 { /*有填充*/
		copy(cipherBlock[:], plainBlock[:8-plainBlock[7]])

		for _, t := range cipherBlock {
			strData = append(strData, t)
		}
	} else { /*无填充*/
		copy(cipherBlock[:], plainBlock[:])
		for _, t := range cipherBlock {
			strData = append(strData, t)
		}
	}

	return strData
}

func (d DES) EncryptFile(cszpSourceFileName string, cszpPwdFileName string, cszpKey_str string) {
	cszpKey := []rune(cszpKey_str)

	count := 0
	var plainBlock [8]int32
	var cipherBlock [8]int32
	var keyBlock [8]int32
	var bKey [64]int32
	var subKeys [16][48]int32

	if checkFileIsExist(cszpSourceFileName) == false {
		panic("cszpSourceFileName 不存在")
	}

	var cipherFile *os.File
	var err1 error
	if checkFileIsExist(cszpPwdFileName) == true {
		os.Remove(cszpPwdFileName)
	}
	cipherFile, err1 = os.Create(cszpPwdFileName) //创建文件
	if err1 != nil {
		panic(err1)
	}
	defer cipherFile.Close() // 安全的关闭文件

	/*设置密钥*/
	copy(keyBlock[:8], cszpKey[:8])
	/*将密钥转换为二进制流*/
	bKey = d.Char8ToBit64(keyBlock, bKey)
	/*生成子密钥*/
	subKeys = d.DES_MakeSubKeys(bKey, subKeys)

	// 读文件
	file, err := os.OpenFile(cszpSourceFileName, os.O_RDWR, 0666)
	if err != nil {
		fmt.Println("Open file error!", err)
		return
	}
	defer file.Close()

	// 写文件
	buf := make([]byte, 8)
	writer := bufio.NewWriter(cipherFile)
	for {
		count, err = file.Read(buf)
		var t_plainBlock []int32
		for _, t := range buf {
			t_plainBlock = append(t_plainBlock, int32(t))
		}
		copy(plainBlock[:], t_plainBlock)

		if err != nil {
			if err == io.EOF {
				break
			} else {
				fmt.Println("Read file error!", err)
				return
			}
		}
		/*每次读8个字节，并返回成功读取的字节数*/
		if count == 8 {
			cipherBlock = d.DES_EncryptBlock(plainBlock, subKeys, cipherBlock)
			var rune_cipherBlock []byte
			for _, t := range cipherBlock {
				rune_cipherBlock = append(rune_cipherBlock, byte(t))
			}
			// 写数据到文件
			_, err1 := writer.Write(rune_cipherBlock) //写入文件(字节数组)
			if err1 != nil {
				panic(err1)
			}
		} else {
			break
		}
	}
	if count > 0 {
		/*填充*/
		/*最后一个字符保存包括最后一个字符在内的所填充的字符数量*/
		plainBlock[7] = int32(8 - count)

		cipherBlock = d.DES_EncryptBlock(plainBlock, subKeys, cipherBlock)
		var rune_cipherBlock []byte
		for _, t := range cipherBlock {
			rune_cipherBlock = append(rune_cipherBlock, byte(t))
		}
		_, err1 := writer.Write(rune_cipherBlock) //写入文件(字节数组)
		if err1 != nil {
			panic(err1)
		}
	}
	writer.Flush()
}

func (d DES) DecryptFile(cszpPwdFileName string, cszpResultFileName string, cszpKey_str string) {
	cszpKey := []rune(cszpKey_str)

	count := 0
	times := 0
	var plainBlock [8]int32
	var cipherBlock [8]int32
	var keyBlock [8]int32
	var bKey [64]int32
	var subKeys [16][48]int32

	if checkFileIsExist(cszpPwdFileName) == false {
		panic("cszpPwdFileName 不存在")
	}

	var plainFile *os.File
	var err1 error
	if checkFileIsExist(cszpResultFileName) == true {
		os.Remove(cszpResultFileName)
	}
	plainFile, err1 = os.Create(cszpResultFileName) //创建文件
	if err1 != nil {
		panic(err1)
	}
	defer plainFile.Close() // 安全的关闭文件

	/*设置密钥*/
	copy(keyBlock[:8], cszpKey[:8])
	/*将密钥转换为二进制流*/
	bKey = d.Char8ToBit64(keyBlock, bKey)
	/*生成子密钥*/
	subKeys = d.DES_MakeSubKeys(bKey, subKeys)

	// 读文件
	file, err := os.OpenFile(cszpPwdFileName, os.O_RDWR, 0666)
	if err != nil {
		fmt.Println("Open file error!", err)
		return
	}
	defer file.Close()
	// 获取加密文件信息
	cipherFileInfo, _ := os.Stat(cszpPwdFileName)
	cszpPwdFileSize := cipherFileInfo.Size()

	// 写文件
	buf := make([]byte, 8)
	writer := bufio.NewWriter(plainFile)
	for {
		count, err = file.Read(buf)
		var t_cipherBlock []int32
		for _, t := range buf {
			t_cipherBlock = append(t_cipherBlock, int32(t))
		}
		copy(cipherBlock[:], t_cipherBlock)

		if err != nil {
			if err == io.EOF {
				break
			} else {
				fmt.Println("Read file error!", err)
				return
			}
		}
		/*每次读8个字节，并返回成功读取的字节数*/
		plainBlock = d.DES_DecryptBlock(cipherBlock, subKeys, plainBlock)
		times += 8
		if times < int(cszpPwdFileSize) {
			var rune_plainBlock []byte
			for _, t := range plainBlock {
				rune_plainBlock = append(rune_plainBlock, byte(t))
			}
			// 写数据到文件
			_, err1 := writer.Write(rune_plainBlock) //写入文件(字节数组)
			if err1 != nil {
				panic(err1)
			}
		} else {
			break
		}
	}
	if int(plainBlock[7]) < 8 {
		count = 8 - int(plainBlock[7])
		for {
			t := plainBlock[count]
			if t != 0 {
				break
			}
			count++
			if count < 7 {
				break
			}
		}
	}
	if count == 7 {
		// 有填充
		var rune_plainBlock []byte
		for _, t := range plainBlock {
			rune_plainBlock = append(rune_plainBlock, byte(t))
		}
		_, err1 := writer.Write(rune_plainBlock[:8-int(plainBlock[7])]) //写入文件(字节数组)
		if err1 != nil {
			panic(err1)
		}
	} else {
		// 无填充
		var rune_plainBlock []byte
		for _, t := range plainBlock {
			rune_plainBlock = append(rune_plainBlock, byte(t))
		}
		_, err1 := writer.Write(rune_plainBlock) //写入文件(字节数组)
		if err1 != nil {
			panic(err1)
		}
	}
	writer.Flush()
}

func checkFileIsExist(filename string) bool {
	var exist = true
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		exist = false
	}
	return exist
}

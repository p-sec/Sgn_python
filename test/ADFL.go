package main

func CipherADFL(data []byte, seed byte) []byte {
	for i := 1; i < len(data)+1; i++ {
		point := len(data) - i
		current := data[point]
		data[point] ^= seed
		seed = byte((int(current) + int(seed)) % 256)
		//seed = byte(byte(current+seed) % 255)
	}
	return data
}

func main() {
	payload := []byte("Hello world!")
	encryptDemo := CipherADFL(payload, 11)
	println(encryptDemo)
}

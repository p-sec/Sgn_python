package main

var ConditionalJumpMnemonics = []string{
	"JAE",
	"JA",
	"JBE",
	"JB",
	"JC",
	"JE",
	"JGE",
	"JG",
	"JLE",
	"JL",
	"JNAE",
	"JNA",
	"JNBE",
	"JNB",
	"JNC",
	"JNE",
	"JNGE",
	"JNG",
	"JNLE",
	"JNL",
	"JNO",
	"JNP",
	"JNS",
	"JNZ",
	"JO",
	"JPE",
	"JPO",
	"JP",
	"JS",
	"JZ",
}

func main() {

	for _, jmp := range ConditionalJumpMnemonics {
		println(jmp + " {L};{G};{L}:")
	}
}

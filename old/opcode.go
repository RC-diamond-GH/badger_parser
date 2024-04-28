func opcode_64(arg1, arg2, arg3 uint64, arg4 uint8) {
	if arg_18 == 0 {
		rax_str := "rax"
		rbx_str := "rbx"
		rcx_str := "rcx"
		rdx_str := "rdx"
		rsi_str := "rsi"
		rdi_str := "rdi"
		r8_str := "r8"
		r9_str := "r9"
		r10_str := "r10"
		r11_str := "r11"
		r12_str := "r12"
		r13_str := "r13"
		r14_str := "r14"
		reg_num := 0x0d
		first_reg_str_addr := &rax_str
	}else {
		rax_str := "rax"
		rbx_str := "rbx"
		rsi_str := "rsi"
		rdi_str := "rdi"
		r8_str := "r8"
		r9_str := "r9"
		r10_str := "r10"
		r11_str := "r11"
		r12_str := "r12"
		r13_str := "r13"
		r14_str := "r14"
		reg_num := 0x0b
		first_reg_str_addr := &rax_str
	}

	if arg2 == 0 {
		return nil
	}

	if arg2 % 8 != 0 {
		add_bytes := make([]uint8, 8 - arg2 % 8)
		for i := 0; i < len(add_bytes); i++ {
			add_bytes[i] = 0x00
		}
		
	}
}
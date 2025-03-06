use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, NasmFormatter};

const HEXBYTES_COLUMN_BYTE_LENGTH: usize = 10;

// slightly modifed from the iced_x86 example - note this function is incredibly poorly done from a performance perspective!
pub fn disassemble(addr: u64, bytes:&[u8]) -> Vec<String>{
    let wordsize = 64;
    let mut decoder = Decoder::with_ip(wordsize, bytes, addr, DecoderOptions::NONE);

    // Formatters: Masm*, Nasm*, Gas* (AT&T) and Intel* (XED).
    // For fastest code, see `SpecializedFormatter` which is ~3.3x faster. Use it if formatting
    // speed is more important than being able to re-assemble formatted instructions.
    let mut formatter = NasmFormatter::new();

    // Change some options, there are many more
    formatter.options_mut().set_digit_separator("`");
    formatter.options_mut().set_first_operand_char_index(10);


    // Initialize this outside the loop because decode_out() writes to every field
    let mut instruction = Instruction::default();

    // The decoder also implements Iterator/IntoIterator so you could use a for loop:
    //      for instruction in &mut decoder { /* ... */ }
    // or collect():
    //      let instructions: Vec<_> = decoder.into_iter().collect();
    // but can_decode()/decode_out() is a little faster:
    let mut res = vec![];
    while decoder.can_decode() {
        // There's also a decode() method that returns an instruction but that also
        // means it copies an instruction (40 bytes):
        //     instruction = decoder.decode();
        decoder.decode_out(&mut instruction);

        let mut output = String::new();
        formatter.format(&instruction, &mut output);

        // Eg. "00007FFAC46ACDB2 488DAC2400FFFFFF     lea       rbp,[rsp-100h]"
        let mut prefix = format!("{:016X} ", instruction.ip());
        let start_index = (instruction.ip() - addr) as usize;
        let instr_bytes = &bytes[start_index..start_index + instruction.len()];
        for b in instr_bytes.iter() {
            prefix.push_str(&format!("{:02X}", b));
        }
        if instr_bytes.len() < HEXBYTES_COLUMN_BYTE_LENGTH {
            for _ in 0..HEXBYTES_COLUMN_BYTE_LENGTH - instr_bytes.len() {
                prefix.push_str("  ");
            }
        }
        prefix.push_str(&output);
        res.push(prefix);
    }
    return res;
}

pub fn disassemble_print(addr: u64, bytes: &[u8]) {
    for line in disassemble(addr, bytes){
        println!("{}", line);
    }
}
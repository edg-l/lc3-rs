use std::{error::Error, fs::File, time::Duration, io::{stdout, Write, stdin, Read}};

use crossterm::event::{Event, KeyCode, KeyEvent};
use thiserror::Error;

#[derive(Debug, Error)]
enum Lc3Error {
    #[error("bad opcode: {0}")]
    BadOpCode(u16),
    #[error("unused opcode: {0:?}")]
    UnusedOpCode(OpCode),
    #[error("bad register: {0}")]
    BadRegister(u16),
    #[error("bad trapcode: {0}")]
    BadTrapCode(u16),
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),
}

#[derive(Debug, Clone, Copy)]
enum Reg {
    R0,
    R1,
    R2,
    R3,
    R4,
    R5,
    R6,
    R7,
    PC,
    Cond,
}

impl TryFrom<u16> for Reg {
    type Error = Lc3Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::R0),
            1 => Ok(Self::R1),
            2 => Ok(Self::R2),
            3 => Ok(Self::R3),
            4 => Ok(Self::R4),
            5 => Ok(Self::R5),
            6 => Ok(Self::R6),
            7 => Ok(Self::R7),
            x => Err(Lc3Error::BadRegister(x)),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum OpCode {
    BR,
    ADD,
    LD,
    ST,
    JSR,
    AND,
    LDR,
    STR,
    RTI,
    NOT,
    LDI,
    STI,
    JMP,
    RES,
    LEA,
    TRAP,
}

impl TryFrom<u16> for OpCode {
    type Error = Lc3Error;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::BR),
            1 => Ok(Self::ADD),
            2 => Ok(Self::LD),
            3 => Ok(Self::ST),
            4 => Ok(Self::JSR),
            5 => Ok(Self::AND),
            6 => Ok(Self::LDR),
            7 => Ok(Self::STR),
            8 => Err(Lc3Error::UnusedOpCode(Self::RTI)),
            9 => Ok(Self::NOT),
            10 => Ok(Self::LDI),
            11 => Ok(Self::STI),
            12 => Ok(Self::JMP),
            13 => Err(Lc3Error::UnusedOpCode(Self::RES)),
            14 => Ok(Self::LEA),
            15 => Ok(Self::TRAP),
            bad => Err(Lc3Error::BadOpCode(bad)),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum CondFlag {
    POS = 1 << 0,
    ZRO = 1 << 1,
    NEG = 1 << 2,
}

#[derive(Debug, Clone, Copy)]
enum TrapCode {
    /// get char from keyboard, not echoed
    GETC = 0x20,
    /// output char
    OUT,
    /// output string
    PUTS,
    /// get char from keyboard, echoed
    IN,
    /// output byte string
    PUTSP,
    /// halt
    HALF,
}

impl TryFrom<u16> for TrapCode {
    type Error = Lc3Error;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x20 => Ok(Self::GETC),
            0x21 => Ok(Self::OUT),
            0x22 => Ok(Self::PUTS),
            0x23 => Ok(Self::IN),
            0x24 => Ok(Self::PUTSP),
            0x25 => Ok(Self::HALF),
            bad => Err(Lc3Error::BadTrapCode(bad)),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum MappedRegister {
    KeyboardStatus = 0xFE00,
    KeyboardData = 0xFE02,
}

const PC_START: u16 = 0x3000;
const MEMORY_MAX: usize = 1 << 16;

#[derive(Debug, Clone)]
struct Registers {
    regs: [u16; Reg::Cond as usize + 1],
}

impl Default for Registers {
    fn default() -> Self {
        Self {
            regs: [0; Reg::Cond as usize + 1],
        }
    }
}

impl std::ops::Index<Reg> for Registers {
    type Output = u16;

    fn index(&self, index: Reg) -> &Self::Output {
        &self.regs[index as usize]
    }
}

impl std::ops::IndexMut<Reg> for Registers {
    fn index_mut(&mut self, index: Reg) -> &mut Self::Output {
        &mut self.regs[index as usize]
    }
}

#[derive(Debug, Clone)]
struct Memory {
    memory: [u16; MEMORY_MAX],
}

//  https://www.jmeiners.com/lc3-vm/#s0:1

impl Default for Memory {
    fn default() -> Self {
        Self {
            memory: [0u16; MEMORY_MAX],
        }
    }
}

impl Memory {
    pub fn read(&mut self, address: u16) -> u16 {
        if address == MappedRegister::KeyboardStatus as u16 {
            if self.check_key() {
                self.memory[MappedRegister::KeyboardStatus as usize] = 1 << 15;
                self.memory[MappedRegister::KeyboardData as usize] = 0 /* todo!("getchar()") */;
            } else {
                self.memory[MappedRegister::KeyboardData as usize] = 0;
            }
        }

        self.memory[address as usize]
    }

    pub fn write(&mut self, address: u16, value: u16) {
        self.memory[address as usize] = value;
    }

    const fn check_key(&self) -> bool {
        todo!()
    }
}

#[derive(Debug, Default)]
struct Lc3 {
    registers: Registers,
    memory: Memory,
}

impl Lc3 {
    pub fn run(&mut self, file: &File) -> Result<(), Lc3Error> {
        Self::disable_input_buffering();

        self.registers[Reg::Cond] = CondFlag::ZRO as u16;
        self.registers[Reg::PC] = PC_START;

        'main: loop {
            let instr = self.read_instruction();
            let op = OpCode::try_from(instr >> 12)?;

            match op {
                OpCode::BR => {
                    let pc_offset = Self::sign_extend(instr & 0x1FF, 9);
                    let cond_flag = (instr >> 9) & 0x7;

                    if cond_flag & self.registers[Reg::Cond] != 0 {
                        self.registers[Reg::PC] += pc_offset;
                    }
                }
                OpCode::ADD => {
                    let r0 = Reg::try_from((instr >> 9) & 0x7)?;
                    let r1 = Reg::try_from((instr >> 6) & 0x7)?;
                    let is_imm = (instr >> 5) & 0x1 != 0;

                    if is_imm {
                        let imm5 = Self::sign_extend(instr & 0x1F, 5);
                        self.registers[r0] = self.registers[r1] + imm5;
                    } else {
                        let r2 = Reg::try_from(instr & 0x7)?;
                        self.registers[r0] = self.registers[r1] + self.registers[r2];
                    }

                    self.update_flags(r0);
                }
                OpCode::LD => {
                    let r0 = Reg::try_from((instr >> 9) & 0x7)?;
                    let pc_offset9 = Self::sign_extend(instr & 0xFF, 8);
                    self.registers[r0] = self.memory.read(self.registers[Reg::PC] + pc_offset9);
                    self.update_flags(r0);
                }
                OpCode::ST => {
                    let r0 = Reg::try_from((instr >> 9) & 0x7)?;
                    let pc_offset9 = Self::sign_extend(instr & 0xFF, 8);
                    self.memory
                        .write(self.registers[Reg::PC] + pc_offset9, self.registers[r0]);
                }
                OpCode::JSR => {
                    let is_long = (instr >> 11) & 0x1 != 0;

                    if is_long {
                        let base = (instr >> 6) & 0x7;
                        self.registers[Reg::PC] = base;
                    } else {
                        let offset = Self::sign_extend((instr >> 11) & 0x7FF, 11);
                        self.registers[Reg::PC] += offset;
                    }
                }
                OpCode::AND => {
                    let r0 = Reg::try_from((instr >> 9) & 0x7)?;
                    let r1 = Reg::try_from((instr >> 6) & 0x7)?;
                    let is_imm = (instr >> 5) & 0x1 != 0;

                    if is_imm {
                        let imm5 = Self::sign_extend(instr & 0x1F, 5);
                        self.registers[r0] = self.registers[r1] & imm5;
                    } else {
                        let r2 = Reg::try_from(instr & 0x7)?;
                        self.registers[r0] = self.registers[r1] & self.registers[r2];
                    }

                    self.update_flags(r0);
                }
                OpCode::LDR => {
                    let r0 = Reg::try_from((instr >> 9) & 0x7)?;
                    let base = (instr >> 6) & 0x7;
                    let offset6 = Self::sign_extend(instr & 0x3F, 6);
                    self.registers[r0] = self.memory.read(base + offset6);
                    self.update_flags(r0);
                }
                OpCode::STR => {
                    let r0 = Reg::try_from((instr >> 9) & 0x7)?;
                    let base = (instr >> 6) & 0x7;
                    let offset6 = Self::sign_extend(instr & 0x3F, 6);
                    self.memory.write(base + offset6, self.registers[r0]);
                }
                OpCode::RTI => unimplemented!(),
                OpCode::NOT => {
                    let r0 = Reg::try_from((instr >> 9) & 0x7)?;
                    let r1 = Reg::try_from((instr >> 6) & 0x7)?;

                    self.registers[r0] = !self.registers[r1];

                    self.update_flags(r0);
                }
                OpCode::LDI => {
                    let r0 = Reg::try_from((instr >> 9) & 0x7)?;
                    let pc_offset = Self::sign_extend(instr & 0x1FF, 9);
                    self.registers[r0] = self.memory.read(self.registers[r0] + pc_offset);
                    self.update_flags(r0);
                }
                OpCode::STI => {
                    let r0 = Reg::try_from((instr >> 9) & 0x7)?;
                    let pc_offset = Self::sign_extend(instr & 0x1FF, 9);
                    let mem_value = self.memory.read(self.registers[Reg::PC] + pc_offset);
                    self.memory.write(mem_value, self.registers[r0]);
                }
                OpCode::JMP => {
                    // handles RET too
                    let r1 = Reg::try_from((instr >> 6) & 0x7)?;
                    self.registers[Reg::PC] = self.registers[r1];
                }
                OpCode::RES => unimplemented!(),
                OpCode::LEA => {
                    let r0 = Reg::try_from((instr >> 9) & 0x7)?;
                    let pc_offset9 = Self::sign_extend(instr & 0xFF, 8);
                    self.registers[r0] = self.registers[Reg::PC] + pc_offset9;
                    self.update_flags(r0);
                }
                OpCode::TRAP => {
                    self.registers[Reg::R7] = self.registers[Reg::PC];

                    let trap_code = TrapCode::try_from(instr & 0xFF)?;

                    match trap_code {
                        TrapCode::GETC => {
                            let mut data = 0;
                            stdin().read_exact(std::slice::from_mut(&mut data))?;
                            self.registers[Reg::R0] = data as u16;
                            self.update_flags(Reg::R0);
                        },
                        TrapCode::OUT => {
                            let data = self.registers[Reg::R0] as u8;
                            stdout().write_all(std::slice::from_ref(&data))?;
                        },
                        TrapCode::PUTS => {
                            let stdout = stdout();
                            let mut handle = stdout.lock();

                            let mut addr = self.registers[Reg::R0];

                            loop {
                                let data = self.memory.read(addr);

                                if data > 0 {
                                    handle.write_all(&[data as u8])?;
                                    addr += 1;
                                } else {
                                    break;
                                }
                            }

                            handle.flush()?;
                        },
                        TrapCode::IN => {
                            stdout().write_all(b"Enter a character: ")?;
                            let mut data = 0;
                            stdin().read_exact(std::slice::from_mut(&mut data))?;
                            stdout().write_all(std::slice::from_ref(&data))?;
                            stdout().flush()?;
                            self.registers[Reg::R0] = data as u16;
                            self.update_flags(Reg::R0);
                        },
                        TrapCode::PUTSP => {
                            let stdout = stdout();
                            let mut handle = stdout.lock();

                            let mut addr = self.registers[Reg::R0];

                            loop {
                                let data = self.memory.read(addr);

                                if data > 0 {
                                    handle.write_all(&data.to_be_bytes())?;
                                    addr += 1;
                                } else {
                                    break;
                                }
                            }

                            handle.flush()?;
                        },
                        TrapCode::HALF => {
                            stdout().write_all(b"HALT")?;
                            break 'main;
                        },
                    }
                }
            }
        }

        Self::enable_input_buffering();

        Ok(())
    }

    fn read_instruction(&mut self) -> u16 {
        let instr = self.memory.read(self.registers[Reg::PC]);
        self.registers[Reg::PC] += 1;
        instr
    }

    fn update_flags(&mut self, reg: Reg) {
        if self.registers[reg] == 0 {
            self.registers[Reg::Cond] = CondFlag::ZRO as u16;
        }
        // Check if negative
        else if self.registers[reg] >> 15 == 1 {
            self.registers[Reg::Cond] = CondFlag::NEG as u16;
        } else {
            self.registers[Reg::Cond] = CondFlag::POS as u16;
        }
    }

    fn disable_input_buffering() {
        crossterm::terminal::enable_raw_mode().expect("should enable raw mode");
    }

    fn enable_input_buffering() {
        crossterm::terminal::disable_raw_mode().expect("should disable raw mode");
    }

    fn check_key() -> bool {
        crossterm::event::poll(Duration::from_secs(0)).unwrap_or(false)
    }

    fn get_key() -> Option<KeyCode> {
        while Self::check_key() {
            if let Event::Key(key) = crossterm::event::read().expect("should read") {
                return Some(key.code);
            }
        }
        None
    }

    const fn sign_extend(mut x: u16, bits: u32) -> u16 {
        if (x >> (bits - 1)) & 1 > 0 {
            x |= 0xFFFF << bits;
        }
        x
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let path = std::env::args().nth(1);

    if let Some(path) = path {
        let file = std::fs::File::open(path)?;

        Lc3::default().run(&file)?;
    } else {
        eprint!("missing path to file");
    }

    //Lc3::default().run();

    Ok(())
}

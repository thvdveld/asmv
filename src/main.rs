use std::{fs::File, io::Read};

use capstone::{
    arch::{
        self,
        arm::{ArmOperand, ArmOperandType},
        ArchDetail, ArchOperand, BuildsCapstone, BuildsCapstoneSyntax,
    },
    Capstone, InsnDetail,
};

use colored::*;
use comfy_table::{
    modifiers::UTF8_ROUND_CORNERS, presets::UTF8_BORDERS_ONLY, ContentArrangement, Table,
};
use object::ObjectSection;
use object::{Object, ObjectSymbol, ObjectSymbolTable};

use clap::Parser;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// List the available symbols in the ELF file.
    #[clap(short, long, action, name = "list-symbols")]
    list_symbols: bool,

    /// The name of the symbol that you want to disassemble.
    #[clap(short, long)]
    symbol: Option<String>,

    /// ELF file that needs disassembly.
    #[clap(value_parser)]
    elf: std::path::PathBuf,
}

fn main() {
    let args = Args::parse();

    let mut buffer = vec![];
    let elf_size = File::open(&args.elf)
        .unwrap()
        .read_to_end(&mut buffer)
        .unwrap();

    let elf_data = &buffer[..elf_size];
    let elf = object::File::parse(elf_data).unwrap();

    struct Symbol {
        name: String,
        address: usize,
        size: usize,
    }

    let mut symbols: Vec<Symbol> = vec![];

    if let Some(symbol_table) = elf.symbol_table() {
        for symbol in symbol_table.symbols() {
            if symbol.size() != 0 {
                symbols.push(Symbol {
                    name: rustc_demangle::demangle(symbol.name().unwrap()).to_string(),
                    address: symbol.address() as usize,
                    size: symbol.size() as usize,
                });
            }
        }
    }

    if args.list_symbols {
        for symbol in &symbols {
            println!("{}", symbol.name);
        }
    } else {
        //ddbug_parser::File::parse(args.elf.to_str().unwrap(), |_| {
        let cs = Capstone::new()
            .arm()
            .mode(arch::arm::ArchMode::Thumb)
            .syntax(arch::arm::ArchSyntax::NoRegName)
            .detail(true)
            .build()
            .expect("Failed to create Capstone object");

        if let Some(section) = elf.section_by_name(".text") {
            let stext = section.address() as usize;
            let text = section.data().unwrap();

            for symbol in &symbols {
                if symbol.size != 0
                    && symbol.address != 0
                    && if let Some(ref s) = args.symbol {
                        symbol.name == *s
                    } else {
                        true
                    }
                {
                    let address = symbol.address;
                    let size = symbol.size;

                    let mut start = if let Some(r) = address.checked_sub(stext) {
                        r
                    } else {
                        continue;
                    };

                    if start >= text.len() {
                        continue;
                    }

                    if start + size >= text.len() {
                        continue;
                    }

                    if start == 0 {
                        start += 1;
                    }

                    println!();
                    println!("{} at 0x{:0x?} (size = {})", symbol.name, address, size);

                    let data = &text[start - 1..][..size];

                    let insns = cs
                        .disasm_all(data, start as u64 + 1)
                        .expect("Failed to disassemble");

                    let mut table = Table::new();
                    table
                        .load_preset(UTF8_BORDERS_ONLY)
                        .apply_modifier(UTF8_ROUND_CORNERS)
                        .set_content_arrangement(ContentArrangement::Dynamic);
                    table.set_header(vec!["Offset", "Operation", "Explanation"]);

                    let mut cmp1 = None;
                    let mut cmp2 = None;
                    let mut additional_row = None;

                    for i in insns.iter() {
                        let detail: InsnDetail =
                            cs.insn_detail(i).expect("Failed to get insn detail");
                        let arch_detail: ArchDetail = detail.arch_detail();
                        let ops = arch_detail.operands();

                        let mut row: Vec<String> = vec![];
                        row.push(format!("0x{:0x?}", i.address()).italic().to_string());
                        row.push(format!(
                            "{} {}",
                            i.mnemonic().unwrap().blue().bold(),
                            i.op_str().unwrap()
                        ));
                        row.push(
                            match i.mnemonic() {
                                Some("udf") => "✘ This is undefined!".red().bold().to_string(),
                                Some("nop") => "sleeping 💤 (or padding)".to_string(),
                                Some("str") | Some("str.w") => {
                                    format!(
                                        "{} = {};",
                                        if let ArchOperand::ArmOperand(ArmOperand {
                                            op_type: ArmOperandType::Mem(mem),
                                            ..
                                        }) = &ops[1]
                                        {
                                            format!(
                                                "{}[{}]",
                                                cs.reg_name(mem.base()).unwrap(),
                                                mem.disp(),
                                            )
                                        } else {
                                            "euhm, I don't know".magenta().to_string()
                                        },
                                        if let ArchOperand::ArmOperand(ArmOperand {
                                            op_type, ..
                                        }) = &ops[0]
                                        {
                                            if let ArmOperandType::Imm(val) = op_type {
                                                format!("0x{val:0x?}")
                                            } else if let ArmOperandType::Reg(reg) = op_type {
                                                cs.reg_name(*reg).unwrap()
                                            } else {
                                                format!("{:?}", ops[1])
                                            }
                                        } else {
                                            format!("{:?}", ops[1])
                                        },
                                    )
                                }
                                Some("mvn") | Some("mvns") => {
                                    format!(
                                        "{} = !{};",
                                        if let ArchOperand::ArmOperand(ArmOperand {
                                            op_type: ArmOperandType::Reg(reg),
                                            ..
                                        }) = &ops[0]
                                        {
                                            cs.reg_name(*reg).unwrap()
                                        } else {
                                            format!("{:?}", ops[0])
                                        },
                                        if let ArchOperand::ArmOperand(ArmOperand {
                                            op_type, ..
                                        }) = &ops[1]
                                        {
                                            if let ArmOperandType::Imm(val) = op_type {
                                                format!("0x{val:0x?}")
                                            } else if let ArmOperandType::Reg(reg) = op_type {
                                                cs.reg_name(*reg).unwrap()
                                            } else {
                                                format!("{:?}", ops[1])
                                            }
                                        } else {
                                            format!("{:?}", ops[1])
                                        },
                                    )
                                }
                                Some("sub") | Some("subs") | Some("sub.w") => {
                                    if ops.len() == 3 {
                                        format!(
                                            "{} = {} - {};",
                                            if let ArchOperand::ArmOperand(ArmOperand {
                                                op_type: ArmOperandType::Reg(reg),
                                                ..
                                            }) = &ops[0]
                                            {
                                                cs.reg_name(*reg).unwrap()
                                            } else {
                                                format!("{:?}", ops[0])
                                            },
                                            if let ArchOperand::ArmOperand(ArmOperand {
                                                op_type,
                                                ..
                                            }) = &ops[1]
                                            {
                                                if let ArmOperandType::Imm(val) = op_type {
                                                    format!("0x{val:0x?}")
                                                } else if let ArmOperandType::Reg(reg) = op_type {
                                                    cs.reg_name(*reg).unwrap()
                                                } else {
                                                    format!("{:?}", ops[1])
                                                }
                                            } else {
                                                format!("{:?}", ops[1])
                                            },
                                            if let ArchOperand::ArmOperand(ArmOperand {
                                                op_type,
                                                ..
                                            }) = &ops[2]
                                            {
                                                if let ArmOperandType::Imm(val) = op_type {
                                                    format!("0x{val:0x?}")
                                                } else if let ArmOperandType::Reg(reg) = op_type {
                                                    cs.reg_name(*reg).unwrap()
                                                } else {
                                                    format!("{:?}", ops[1])
                                                }
                                            } else {
                                                format!("{:?}", ops[1])
                                            },
                                        )
                                    } else {
                                        format!(
                                            "{} -= {};",
                                            if let ArchOperand::ArmOperand(ArmOperand {
                                                op_type: ArmOperandType::Reg(reg),
                                                ..
                                            }) = &ops[0]
                                            {
                                                cs.reg_name(*reg).unwrap()
                                            } else {
                                                format!("{:?}", ops[0])
                                            },
                                            if let ArchOperand::ArmOperand(ArmOperand {
                                                op_type,
                                                ..
                                            }) = &ops[1]
                                            {
                                                if let ArmOperandType::Imm(val) = op_type {
                                                    format!("0x{val:0x?}")
                                                } else if let ArmOperandType::Reg(reg) = op_type {
                                                    cs.reg_name(*reg).unwrap()
                                                } else {
                                                    format!("{:?}", ops[1])
                                                }
                                            } else {
                                                format!("{:?}", ops[1])
                                            },
                                        )
                                    }
                                }
                                Some("add") | Some("adds") | Some("add.w") => {
                                    if ops.len() == 3 {
                                        format!(
                                            "{} = {} + {};",
                                            if let ArchOperand::ArmOperand(ArmOperand {
                                                op_type: ArmOperandType::Reg(reg),
                                                ..
                                            }) = &ops[0]
                                            {
                                                cs.reg_name(*reg).unwrap()
                                            } else {
                                                format!("{:?}", ops[0])
                                            },
                                            if let ArchOperand::ArmOperand(ArmOperand {
                                                op_type,
                                                ..
                                            }) = &ops[1]
                                            {
                                                if let ArmOperandType::Imm(val) = op_type {
                                                    format!("0x{val:0x?}")
                                                } else if let ArmOperandType::Reg(reg) = op_type {
                                                    cs.reg_name(*reg).unwrap()
                                                } else {
                                                    format!("{:?}", ops[1])
                                                }
                                            } else {
                                                format!("{:?}", ops[1])
                                            },
                                            if let ArchOperand::ArmOperand(ArmOperand {
                                                op_type,
                                                ..
                                            }) = &ops[2]
                                            {
                                                if let ArmOperandType::Imm(val) = op_type {
                                                    format!("0x{val:0x?}")
                                                } else if let ArmOperandType::Reg(reg) = op_type {
                                                    cs.reg_name(*reg).unwrap()
                                                } else {
                                                    format!("{:?}", ops[1])
                                                }
                                            } else {
                                                format!("{:?}", ops[1])
                                            },
                                        )
                                    } else {
                                        format!(
                                            "{} += {};",
                                            if let ArchOperand::ArmOperand(ArmOperand {
                                                op_type: ArmOperandType::Reg(reg),
                                                ..
                                            }) = &ops[0]
                                            {
                                                cs.reg_name(*reg).unwrap()
                                            } else {
                                                format!("{:?}", ops[0])
                                            },
                                            if let ArchOperand::ArmOperand(ArmOperand {
                                                op_type,
                                                ..
                                            }) = &ops[1]
                                            {
                                                if let ArmOperandType::Imm(val) = op_type {
                                                    format!("0x{val:0x?}")
                                                } else if let ArmOperandType::Reg(reg) = op_type {
                                                    cs.reg_name(*reg).unwrap()
                                                } else {
                                                    format!("{:?}", ops[1])
                                                }
                                            } else {
                                                format!("{:?}", ops[1])
                                            },
                                        )
                                    }
                                }
                                Some("it") => {
                                    format!(
                                        "if {} != {}",
                                        if let Some(ArchOperand::ArmOperand(ArmOperand {
                                            op_type: ArmOperandType::Reg(reg),
                                            ..
                                        })) = cmp1
                                        {
                                            cs.reg_name(reg).unwrap()
                                        } else {
                                            "?".to_string()
                                        },
                                        if let Some(ArchOperand::ArmOperand(ArmOperand {
                                            op_type: ArmOperandType::Imm(val),
                                            ..
                                        })) = cmp2
                                        {
                                            val.to_string()
                                        } else if let Some(ArchOperand::ArmOperand(ArmOperand {
                                            op_type: ArmOperandType::Reg(reg),
                                            ..
                                        })) = cmp2
                                        {
                                            cs.reg_name(reg).unwrap()
                                        } else {
                                            "?".to_string()
                                        },
                                    )
                                }
                                b @ (Some("beq") | Some("bne") | Some("bhs") | Some("b")
                                | Some("b.w")) => {
                                    additional_row = Some(vec![]);
                                    let condition = match b {
                                        Some("beq") => format!(
                                            "if {} == {}:",
                                            if let Some(ArchOperand::ArmOperand(ArmOperand {
                                                op_type: ArmOperandType::Reg(reg),
                                                ..
                                            })) = cmp1
                                            {
                                                cs.reg_name(reg).unwrap()
                                            } else {
                                                format!("{:?}", cmp1)
                                            },
                                            if let Some(ArchOperand::ArmOperand(ArmOperand {
                                                op_type: ArmOperandType::Imm(val),
                                                ..
                                            })) = cmp2
                                            {
                                                format!("0x{val:0x?}")
                                            } else if let Some(ArchOperand::ArmOperand(
                                                ArmOperand {
                                                    op_type: ArmOperandType::Reg(reg),
                                                    ..
                                                },
                                            )) = cmp2
                                            {
                                                cs.reg_name(reg).unwrap()
                                            } else {
                                                format!("{:?}", cmp2)
                                            },
                                        ),
                                        Some("bne") => format!(
                                            "if {} != {}:",
                                            if let Some(ArchOperand::ArmOperand(ArmOperand {
                                                op_type: ArmOperandType::Reg(reg),
                                                ..
                                            })) = cmp1
                                            {
                                                cs.reg_name(reg).unwrap()
                                            } else {
                                                format!("{:?}", cmp1)
                                            },
                                            if let Some(ArchOperand::ArmOperand(ArmOperand {
                                                op_type: ArmOperandType::Imm(val),
                                                ..
                                            })) = cmp2
                                            {
                                                format!("0x{val:0x?}")
                                            } else if let Some(ArchOperand::ArmOperand(
                                                ArmOperand {
                                                    op_type: ArmOperandType::Reg(reg),
                                                    ..
                                                },
                                            )) = cmp2
                                            {
                                                cs.reg_name(reg).unwrap()
                                            } else {
                                                format!("{:?}", cmp2)
                                            },
                                        ),
                                        Some("b") | Some("bhs") | Some("b.w") => String::new(),
                                        _ => unreachable!(),
                                    };
                                    format!(
                                        //"  ➤ goto {}",
                                        "⮩ {condition} goto {};",
                                        if let ArchOperand::ArmOperand(ArmOperand {
                                            op_type: ArmOperandType::Imm(a),
                                            ..
                                        }) = &ops[0]
                                        {
                                            format!("0x{:0x?}", a).bold().to_string()
                                        } else {
                                            "??".red().bold().to_string()
                                        }
                                    )
                                }
                                Some("bl") => {
                                    additional_row = Some(vec![]);
                                    format!("⮩ {};", {
                                        let mut destination = "unknown".red().bold().to_string();

                                        for s in &symbols {
                                            if let ArchOperand::ArmOperand(ArmOperand {
                                                op_type: ArmOperandType::Imm(a),
                                                ..
                                            }) = &ops[0]
                                            {
                                                if s.address - stext + 1 == *a as usize {
                                                    destination = s.name.clone().bold().to_string();

                                                    if destination.contains("panic") {
                                                        destination =
                                                            destination.red().italic().to_string();
                                                    }
                                                }
                                            }
                                        }

                                        destination
                                    })
                                }
                                Some("cmp") => {
                                    cmp1 = Some(ops[0].clone());
                                    cmp2 = Some(ops[1].clone());
                                    String::new()
                                }
                                Some("pop") | Some("pop.w") => {
                                    let mut regs: Vec<String> = ops
                                        .iter()
                                        .map(|op| {
                                            if let ArchOperand::ArmOperand(ArmOperand {
                                                op_type: ArmOperandType::Reg(reg),
                                                ..
                                            }) = op
                                            {
                                                cs.reg_name(*reg).unwrap()
                                            } else {
                                                format!("{:?}", op)
                                            }
                                        })
                                        .collect();

                                    if regs.contains(&String::from("pc")) {
                                        regs.retain(|r| r != "pc");
                                        additional_row = Some(vec![
                                            String::new(),
                                            String::new(),
                                            "return;".bold().green().to_string(),
                                        ]);
                                        format!("pop({});", regs.join(", "))
                                    } else {
                                        format!("pop({});", regs.join(", "))
                                    }
                                }
                                Some("push") | Some("push.w") => {
                                    let regs: Vec<String> = ops
                                        .iter()
                                        .map(|op| {
                                            if let ArchOperand::ArmOperand(ArmOperand {
                                                op_type: ArmOperandType::Reg(reg),
                                                ..
                                            }) = op
                                            {
                                                cs.reg_name(*reg).unwrap()
                                            } else {
                                                format!("{:?}", op)
                                            }
                                        })
                                        .collect();
                                    format!("push({});", regs.join(", "))
                                }
                                Some("movs") | Some("mov") | Some("movw") | Some("mov.w") => {
                                    format!(
                                        "{} = {};",
                                        if let ArchOperand::ArmOperand(ArmOperand {
                                            op_type: ArmOperandType::Reg(reg),
                                            ..
                                        }) = &ops[0]
                                        {
                                            cs.reg_name(*reg).unwrap()
                                        } else {
                                            format!("{:?}", ops[0])
                                        },
                                        if let ArchOperand::ArmOperand(ArmOperand {
                                            op_type, ..
                                        }) = &ops[1]
                                        {
                                            if let ArmOperandType::Imm(val) = op_type {
                                                format!("0x{val:0x?}")
                                            } else if let ArmOperandType::Reg(reg) = op_type {
                                                cs.reg_name(*reg).unwrap()
                                            } else {
                                                format!("{:?}", ops[1])
                                            }
                                        } else {
                                            format!("{:?}", ops[1])
                                        },
                                    )
                                }
                                Some("movt") => {
                                    format!(
                                        "({} & 0xffff_0000) = {};",
                                        if let ArchOperand::ArmOperand(ArmOperand {
                                            op_type: ArmOperandType::Reg(reg),
                                            ..
                                        }) = &ops[0]
                                        {
                                            cs.reg_name(*reg).unwrap()
                                        } else {
                                            format!("{:?}", ops[0])
                                        },
                                        if let ArchOperand::ArmOperand(ArmOperand {
                                            op_type, ..
                                        }) = &ops[1]
                                        {
                                            if let ArmOperandType::Imm(val) = op_type {
                                                format!("0x{val:0x?}")
                                            } else if let ArmOperandType::Reg(reg) = op_type {
                                                cs.reg_name(*reg).unwrap()
                                            } else {
                                                format!("{:?}", ops[1])
                                            }
                                        } else {
                                            format!("{:?}", ops[1])
                                        },
                                    )
                                }
                                _ => "".to_string(),
                            }
                            .green()
                            .to_string(),
                        );
                        table.add_row(row);

                        if let Some(row) = additional_row {
                            table.add_row(row);
                        }
                        additional_row = None;
                    }

                    println!("{table}");
                }
            }
        }
        //Ok(());
        //})
        //.unwrap();
    }
}

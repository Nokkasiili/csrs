#[macro_use]
extern crate bitflags;
use byteorder::{LittleEndian, ReadBytesExt};
use scroll::Pread;
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::SeekFrom;
use std::io::{prelude::*, BufReader};
use std::path::PathBuf;

#[derive(Debug)]
struct Process {
    pid: String,
    maps: Vec<Map>,
}
bitflags! {
struct Perms:u8{
    const NONE=0x0;
    const READ=0x1;
    const WRITE=0x2;
    const EXEC=0x4;
    const SHARED=0x8;
    const PRIVATE=0x16;
}

}

#[derive(Debug, Eq, PartialEq)]
struct Map {
    begin: u64,   //0
    end: u64,     //0
    perms: Perms, //1
    offset: u64,  //2
    dev: String,  //3
    inode: u64,   //4
    name: String, //5
}

#[derive(Debug)]
struct Csgo {
    netvars: HashMap<String, u64>,
    interfaces: HashMap<String, u64>,
    cvars: HashMap<String, u64>,
}

#[derive(Debug)]
struct Elf {
    ehdr: goblin::elf64::header::Header,
    phdr: goblin::elf64::program_header::ProgramHeader,
    syms: HashMap<String, goblin::elf::sym::sym64::Sym>,
    dyns: HashMap<u64, u64>,
}

fn proc_path(pid: &str, file_name: &str) -> PathBuf {
    PathBuf::from("/proc/").join(pid).join(file_name)
}

fn string_from_bytes(bytes: &Vec<u8>, index: usize) -> Option<String> {
    for i in index..bytes.len() {
        if bytes.get(i) == Some(&0) {
            return Some(String::from_utf8_lossy(&bytes[index..i]).to_string());
        }
    }
    None
}
fn read_ptr(f: &mut File, offset: u64) -> Result<u64, Box<dyn Error>> {
    f.seek(SeekFrom::Start(offset))?;
    let ptr = f.read_u64::<LittleEndian>()?;
    f.seek(SeekFrom::Start(ptr))?;
    let ptr = f.read_u64::<LittleEndian>()?;
    Ok(ptr)
}

impl Csgo {
    fn new(f: &mut File, offset: u64, elf: &Elf) -> Result<Csgo, Box<dyn Error>> {
        let interface = Csgo::parse_interfaces(f, offset, elf)?;

        let vclient = interface.get("VClient");
        let mut netvar = HashMap::new();

        if vclient.is_some() {
            netvar = Csgo::parse_netvar(f, *vclient.unwrap())?;
        }

        let venginecvar = interface.get("VEngineCvar");
        let mut cvars = HashMap::new();
        if venginecvar.is_some() {
            cvars = Csgo::parse_cvars(f, *venginecvar.unwrap())?;
        }
        Ok(Csgo {
            interfaces: interface,
            netvars: netvar,
            cvars: cvars,
        })
    }

    fn parse_cvars(f: &mut File, offset: u64) -> Result<HashMap<String, u64>, Box<dyn Error>> {
        let mut ret: HashMap<String, u64> = HashMap::new();

        f.seek(SeekFrom::Start(offset + 0x70))?;
        let mut cur_cvar = f.read_u64::<LittleEndian>()?;
        loop {
            f.seek(SeekFrom::Start(cur_cvar + 0x18))?;
            let cvar_ptr = f.read_u64::<LittleEndian>()?;
            f.seek(SeekFrom::Start(cvar_ptr))?;

            let mut str_cvar = [0u8; 256]; //read unknown size string
            f.read_exact(&mut str_cvar)?;
            let name = string_from_bytes(&str_cvar.to_vec(), 0).unwrap();
            ret.insert(name, cur_cvar);
            f.seek(SeekFrom::Start(cur_cvar + 0x8))?;
            cur_cvar = f.read_u64::<LittleEndian>().unwrap_or_default();
            if cur_cvar == 0 {
                break;
            }
        }

        Ok(ret)
    }
    fn parse_netvar(f: &mut File, offset: u64) -> Result<HashMap<String, u64>, Box<dyn Error>> {
        let mut ret: HashMap<String, u64> = HashMap::new();
        f.seek(SeekFrom::Start(offset + 8 * 8))?; //vtable[8]
        let mut cur_netvar = f.read_u64::<LittleEndian>()?;
        f.seek(SeekFrom::Start(cur_netvar + 3))?;
        let offset_netvar = f.read_i32::<LittleEndian>()? as u64;

        cur_netvar = read_ptr(f, cur_netvar + offset_netvar + 7)?;

        loop {
            f.seek(SeekFrom::Start(cur_netvar + 0x18))?;
            let char_ptr = f.read_u64::<LittleEndian>()?;
            f.seek(SeekFrom::Start(char_ptr + 0x18))?;
            let char_ptr = f.read_u64::<LittleEndian>()?;
            f.seek(SeekFrom::Start(char_ptr))?;
            let mut str_netvar = [0u8; 256]; //read unknown size string
            f.read_exact(&mut str_netvar)?;
            let name = string_from_bytes(&str_netvar.to_vec(), 0).unwrap();
            ret.insert(name, char_ptr);
            f.seek(SeekFrom::Start(cur_netvar + 0x20))?;
            cur_netvar = f.read_u64::<LittleEndian>().unwrap_or_default();
            if cur_netvar == 0 {
                break;
            }
        }

        Ok(ret)
    }

    fn parse_interfaces(
        f: &mut File,
        offset: u64,
        elf: &Elf,
    ) -> Result<HashMap<String, u64>, Box<dyn Error>> {
        let mut ret: HashMap<String, u64> = HashMap::new();
        let sym = elf.syms.get("s_pInterfaceRegs");
        if sym.is_none() {
            Err("no s_pInterfaceRegs")?;
        }
        let sym = sym.unwrap();

        f.seek(SeekFrom::Start(offset + sym.st_value))?;
        let mut cur_interface = f.read_u64::<LittleEndian>()?;

        loop {
            /*
            void * func;
            char * name;
            interface *next;*/
            //read name
            f.seek(SeekFrom::Start(cur_interface + 8))?; //follow char pointer
            let pname = f.read_u64::<LittleEndian>()?;

            f.seek(SeekFrom::Start(pname))?;
            let mut pname_str = [0u8; 256]; //read unknown size string
            f.read_exact(&mut pname_str)?;
            //trim it with our nice func
            let name = string_from_bytes(&pname_str.to_vec(), 0).unwrap();
            let name = name.trim_end_matches(char::is_numeric).to_string();

            //read func
            f.seek(SeekFrom::Start(cur_interface))?;
            let func = f.read_u64::<LittleEndian>()?;
            f.seek(SeekFrom::Start(func))?;
            let c = f.read_u8()?;

            //no idea what this does but it works i think :D
            let vftptr: u64 = match c {
                0x48 => {
                    f.seek(SeekFrom::Start(func + 3))?;
                    let mut offset = f.read_i32::<LittleEndian>()? as u64;
                    offset = offset.wrapping_add(func + 7);
                    f.seek(SeekFrom::Start(offset))?;
                    let t = f.read_u64::<LittleEndian>()?;
                    t
                }
                _ => {
                    f.seek(SeekFrom::Start(func + 1 + 3))?;
                    let offset = f.read_i32::<LittleEndian>()? as u64;
                    offset.wrapping_add(func + 8)
                }
            };
            f.seek(SeekFrom::Start(vftptr))?;
            //not sure why this needs unwrap_or_default
            //and why it even works with default value
            let vftbase = f.read_u64::<LittleEndian>().unwrap_or_default();
            ret.insert(name, vftbase);

            //next
            f.seek(SeekFrom::Start(cur_interface + 0x10))?;
            cur_interface = f.read_u64::<LittleEndian>()?;
            if cur_interface == 0 {
                break;
            }
        }

        Ok(ret)
    }
}

impl Elf {
    fn parse_syms(
        f: &mut File,
        dyns: &HashMap<u64, u64>,
    ) -> Result<HashMap<String, goblin::elf::sym::sym64::Sym>, Box<dyn Error>> {
        let mut ret: HashMap<String, goblin::elf::sym::sym64::Sym> = HashMap::new();
        let symtab = dyns.get(&goblin::elf64::dynamic::DT_SYMTAB);
        let strsz = dyns.get(&goblin::elf64::dynamic::DT_STRSZ);
        let strtab = dyns.get(&goblin::elf64::dynamic::DT_STRTAB);
        if symtab.is_none() || strsz.is_none() || strtab.is_none() {
            return Err("not enough data to parse syms")?;
        }
        //hack :D
        let symtab = symtab.unwrap();
        let strsz = strsz.unwrap();
        let strtab = strtab.unwrap();

        let mut strs = vec![0u8; *strsz as usize];
        f.seek(SeekFrom::Start(*strtab))?;
        f.read_exact(&mut strs)?;
        let mut i = 0;
        loop {
            f.seek(SeekFrom::Start(
                *symtab + i * (goblin::elf::sym::sym64::SIZEOF_SYM as u64),
            ))?;
            let mut s = [0u8; goblin::elf::sym::sym64::SIZEOF_SYM];
            f.read_exact(&mut s)?;
            let sym: goblin::elf::sym::sym64::Sym = s.pread(0)?;
            if sym.st_name as u64 > *strsz {
                break;
            }
            if sym.st_value == 0 {
                i += 1;
                continue;
            }
            let name = string_from_bytes(&strs, sym.st_name as usize);
            ret.insert(name.unwrap(), sym);
            i = i + 1;
        }
        Ok(ret)
    }
    fn parse_dyns(
        f: &mut File,
        start: u64,
        phdr: &goblin::elf64::program_header::ProgramHeader,
    ) -> Result<HashMap<u64, u64>, Box<dyn Error>> {
        let mut ret: HashMap<u64, u64> = HashMap::new();

        let size = goblin::elf64::dynamic::SIZEOF_DYN as u64;
        let count = phdr.p_memsz / size;
        for i in 0..count {
            let offset: u64 = i * size;
            f.seek(SeekFrom::Start(start + phdr.p_paddr + offset))?;
            let mut d = [0u8; goblin::elf64::dynamic::SIZEOF_DYN];
            f.read_exact(&mut d)?;
            let d: goblin::elf64::dynamic::Dyn = d.pread(0)?;
            ret.insert(d.d_tag, d.d_val);
        }
        Ok(ret)
    }

    fn parse_phdr(
        f: &mut File,
        start: u64,
        header: &goblin::elf64::header::Header,
    ) -> Result<goblin::elf64::program_header::ProgramHeader, Box<dyn Error>> {
        for i in 0..header.e_phnum {
            let offset: u64 = (i * header.e_phentsize) as u64;
            f.seek(SeekFrom::Start(start + header.e_phoff + offset))?;
            let mut phdr = [0u8; goblin::elf64::program_header::SIZEOF_PHDR];
            f.read_exact(&mut phdr)?;
            let phdr: goblin::elf64::program_header::ProgramHeader = phdr.pread(0)?;
            if phdr.p_type == goblin::elf64::program_header::PT_DYNAMIC {
                return Ok(phdr);
            }
        }
        Err("didnt found dynamic")?
    }
    fn parse_ehdr(
        f: &mut File,
        start: u64,
    ) -> Result<goblin::elf64::header::Header, Box<dyn Error>> {
        f.seek(SeekFrom::Start(start))?;
        let mut header = [0u8; goblin::elf64::header::SIZEOF_EHDR];
        f.read_exact(&mut header)?;
        let header: goblin::elf64::header::Header = header.pread(0)?;
        Ok(header)
    }
    fn new(f: &mut File, start: u64) -> Result<Elf, Box<dyn Error>> {
        let ehdr = Elf::parse_ehdr(f, start)?;
        if &ehdr.e_ident[..goblin::elf64::header::ELFMAG.len()] != goblin::elf64::header::ELFMAG {
            Err("not elf")?;
        }
        if ehdr.e_machine != goblin::elf64::header::EM_X86_64 {
            Err("not 64bit")?;
        }
        //Phdr
        let dynamic = Elf::parse_phdr(f, start, &ehdr)?;
        let dyns = Elf::parse_dyns(f, start, &dynamic)?;
        let sym = Elf::parse_syms(f, &dyns)?;
        Ok(Elf {
            ehdr: ehdr,
            phdr: dynamic,
            syms: sym,
            dyns: dyns,
        })
    }
}

impl Map {
    fn parse_map(line: &str) -> Option<Map> {
        let split: Vec<&str> = line.split_whitespace().collect();
        if split.len() < 5 {
            return None;
        }
        let offsets: Vec<&str> = split[0].split("-").collect();
        if offsets.len() != 2 {
            return None;
        }
        let mut perm: Perms = Perms::NONE;
        for p in split[1].chars() {
            match p {
                'w' => perm |= Perms::WRITE,
                's' => perm |= Perms::SHARED,
                'r' => perm |= Perms::READ,
                'p' => perm |= Perms::PRIVATE,
                'x' => perm |= Perms::EXEC,
                _ => {
                    continue;
                }
            }
        }

        Some(Map {
            begin: u64::from_str_radix(offsets[0], 16).unwrap_or_default(),
            end: u64::from_str_radix(offsets[1], 16).unwrap_or_default(),
            perms: perm,
            offset: u64::from_str_radix(split[2], 16).unwrap_or_default(),
            dev: split[3].to_owned(),
            inode: split[4].parse::<u64>().unwrap_or_default(),
            name: {
                if split.len() >= 5 {
                    split[5..].join(" ").to_owned()
                } else {
                    "".to_owned()
                }
            },
        })
    }
    fn get_maps(pid: &str) -> Result<Vec<Map>, Box<dyn Error>> {
        let mut ret: Vec<Map> = Vec::new();
        let p = proc_path(pid, "maps");
        let file = File::open(p)?;
        let reader = BufReader::new(file);

        for line in reader.lines() {
            if let Ok(ip) = line {
                if let Some(map) = Map::parse_map(&ip) {
                    ret.push(map);
                }
            }
        }

        Ok(ret)
    }
}

impl Process {
    fn contains_name(e: &fs::DirEntry, process_name: &str) -> bool {
        let p = proc_path(e.path().to_str().unwrap(), "cmdline");
        let s = fs::read_to_string(&p).unwrap_or_default();

        s.contains(process_name)
    }
    fn from_name(process_name: &str) -> Result<String, Box<dyn Error>> {
        let files = fs::read_dir("/proc")?;
        for entry in files {
            if let Ok(entry) = entry {
                if Process::contains_name(&entry, process_name) {
                    return Ok(entry.file_name().to_str().unwrap().to_owned());
                }
            }
        }
        Err("not found")?
    }
}

trait FindMap {
    fn find_map(&self, s: &str) -> Option<&Map>;
}
impl FindMap for Vec<Map> {
    fn find_map(&self, s: &str) -> Option<&Map> {
        let pos = self.into_iter().position(|m| m.name.ends_with(s)).unwrap();

        self.get(pos)
    }
}

fn main() {
    let l = Process::from_name("csgo_linux64").unwrap();
    let maps: Vec<Map> = Map::get_maps(&l).unwrap().into_iter().collect();
    let path = proc_path(&l, "mem");
    let mut f = File::open(path).unwrap();

    for s in maps {
        println!("Map:{}", s.name);
        let elf = Elf::new(&mut f, s.begin);
        if elf.is_err() {
            continue;
        }
        let csgo = Csgo::new(&mut f, s.begin, &elf.unwrap());
        if csgo.is_err() {
            continue;
        }
        let csgo = csgo.unwrap();
        for i in csgo.interfaces {
            println!("\t Interface:{:?}", i);
        }
        for i in csgo.cvars {
            println!("\t Cvars:{:?}", i);
        }
        for i in csgo.netvars {
            println!("\t Netvars:{:?}", i);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_map_parse() {
        let map = Map {
            begin: 230613454848,
            end: 230613458944,
            perms: Perms::READ | Perms::EXEC | Perms::PRIVATE,
            offset: 00000000,
            dev: "08:02".to_string(),
            inode: 173521,
            name: "/usr/bin/fak".to_string(),
        };
        let s = "35b1a21000-35b1a22000 r-xp 00000000 08:02 173521      /usr/bin/fak";
        let space =
            "35b1a21000-35b1a22000 r-xp 00000000 08:02 173521      /usr/bin/space space/t.so";
        assert_eq!(map, Map::parse_map(s).unwrap());
        assert_eq!(
            "/usr/bin/space space/t.so",
            Map::parse_map(space).unwrap().name
        );
    }
}

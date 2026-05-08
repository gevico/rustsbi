use alloc::vec::Vec;
use serde::Deserialize;
use serde_device_tree::{
    Dtb, DtbPtr,
    buildin::{Node, NodeSeq, Reg, StrSeq},
    value::riscv_pmu::{EventToMhpmcounters, EventToMhpmevent, RawEventToMhpcounters},
};

use crate::cfg::NUM_HART_MAX;
use core::ops::Range;

/// Root device tree structure containing system information.
#[derive(Deserialize)]
pub struct Tree<'a> {
    /// Optional model name string.
    pub model: Option<StrSeq<'a>>,
    /// Memory information.
    pub memory: NodeSeq<'a>,
    /// CPU information.
    pub cpus: Cpus<'a>,
}

/// CPU information container.
#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Cpus<'a> {
    /// Sequence of CPU nodes.
    pub cpu: NodeSeq<'a>,
}

/// Individual CPU node information.
#[derive(Deserialize, Debug)]
pub struct Cpu<'a> {
    /// RISC-V ISA extensions supported by this CPU.
    #[serde(rename = "riscv,isa-extensions")]
    pub isa_extensions: Option<StrSeq<'a>>,
    #[serde(rename = "riscv,isa")]
    pub isa: Option<StrSeq<'a>>,
    /// CPU register information.
    pub reg: Reg<'a>,
}

/// Generic device node information.
#[allow(unused)]
#[derive(Deserialize, Debug)]
pub struct Device<'a> {
    /// Device register information.
    pub reg: Reg<'a>,
}

/// Memory range.
#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Memory<'a> {
    pub reg: Reg<'a>,
}

#[derive(Deserialize)]
pub struct Pmu<'a> {
    #[serde(rename = "riscv,event-to-mhpmevent")]
    pub event_to_mhpmevent: Option<EventToMhpmevent<'a>>,
    #[serde(rename = "riscv,event-to-mhpmcounters")]
    pub event_to_mhpmcounters: Option<EventToMhpmcounters<'a>>,
    #[serde(rename = "riscv,raw-event-to-mhpmcounters")]
    pub raw_event_to_mhpmcounters: Option<RawEventToMhpcounters<'a>>,
}

/// Errors that can occur during device tree parsing.
pub enum ParseDeviceTreeError {
    /// Invalid device tree format.
    Format,
}

pub struct K230DtbInfo {
    pub memory_range: Option<Range<usize>>,
    pub console_base: Option<usize>,
    pub clint_base: Option<usize>,
    pub cpu_num: usize,
    pub enabled_harts: [usize; NUM_HART_MAX],
    pub enabled_hart_count: usize,
}

type K230ProbeNode = u16;

const K230_NODE_ROOT: K230ProbeNode = 0x0101;
const K230_NODE_CPUS: K230ProbeNode = 0x0211;
const K230_NODE_CPU: K230ProbeNode = 0x0323;
const K230_NODE_SOC: K230ProbeNode = 0x0447;
const K230_NODE_MEMORY: K230ProbeNode = 0x0589;
const K230_NODE_SERIAL: K230ProbeNode = 0x06ab;
const K230_NODE_CLINT: K230ProbeNode = 0x07cd;
const K230_NODE_OTHER: K230ProbeNode = 0x08ef;

pub fn is_k230_device_tree(fdt_address: usize) -> bool {
    probe_k230_dtb(fdt_address).is_some()
}

pub fn probe_k230_dtb(fdt_address: usize) -> Option<K230DtbInfo> {
    const FDT_MAGIC: u32 = 0xd00d_feed;
    const FDT_BEGIN_NODE: u32 = 0x1;
    const FDT_END_NODE: u32 = 0x2;
    const FDT_PROP: u32 = 0x3;
    const FDT_NOP: u32 = 0x4;
    const FDT_END: u32 = 0x9;
    const MAX_DTB_SIZE: usize = 16 * 1024 * 1024;

    let header = fdt_address as *const u8;
    let magic = unsafe { read_be32_ptr(header, 0)? };
    if magic != FDT_MAGIC {
        return None;
    }
    let total_size = unsafe { read_be32_ptr(header, 4)? as usize };
    if total_size == 0 || total_size > MAX_DTB_SIZE {
        return None;
    }
    let blob = unsafe { core::slice::from_raw_parts(header, total_size) };
    let off_struct = read_be32(blob, 8)? as usize;
    let off_strings = read_be32(blob, 12)? as usize;
    let size_strings = read_be32(blob, 32)? as usize;
    let size_struct = read_be32(blob, 36)? as usize;
    let structure = checked_slice(blob, off_struct, size_struct)?;
    let strings = checked_slice(blob, off_strings, size_strings)?;

    let mut info = K230DtbInfo {
        memory_range: None,
        console_base: None,
        clint_base: None,
        cpu_num: 0,
        enabled_harts: [0; NUM_HART_MAX],
        enabled_hart_count: 0,
    };
    let mut is_k230 = false;
    let mut root_address_cells = 2usize;
    let mut root_size_cells = 1usize;
    let mut soc_address_cells = 2usize;
    let mut soc_size_cells = 1usize;
    let mut cpus_address_cells = 1usize;
    let mut node_stack = [K230_NODE_OTHER; 16];
    let mut depth = 0usize;
    let mut cursor = 0usize;

    while cursor < structure.len() {
        let token = read_be32(structure, cursor)?;
        cursor = cursor.checked_add(4)?;
        if token_eq(token, FDT_BEGIN_NODE) {
            let name = read_struct_name(structure, &mut cursor)?;
            let parent = if depth == 0 {
                K230_NODE_OTHER
            } else {
                node_stack[depth - 1]
            };
            let node = classify_k230_node(depth, parent, name);
            if depth >= node_stack.len() {
                return None;
            }
            node_stack[depth] = node;
            depth += 1;
            if node_eq(node, K230_NODE_CPU) {
                info.cpu_num += 1;
            }
        } else if token_eq(token, FDT_END_NODE) {
            depth = depth.checked_sub(1)?;
        } else if token_eq(token, FDT_PROP) {
            let len = read_be32(structure, cursor)? as usize;
            cursor = cursor.checked_add(4)?;
            let nameoff = read_be32(structure, cursor)? as usize;
            cursor = cursor.checked_add(4)?;
            let value = checked_slice(structure, cursor, len)?;
            cursor = align4(cursor.checked_add(len)?);
            let prop_name = string_at(strings, nameoff)?;
            let current = if depth == 0 {
                K230_NODE_OTHER
            } else {
                node_stack[depth - 1]
            };

            if prop_name == b"compatible" && string_list_contains(value, b"kendryte,k230") {
                is_k230 = true;
            } else if prop_name == b"model" && string_value_eq(value, b"kendryte,k230") {
                is_k230 = true;
            } else if node_eq(current, K230_NODE_ROOT) && prop_name == b"#address-cells" {
                root_address_cells = read_cell_count(value)?;
            } else if node_eq(current, K230_NODE_ROOT) && prop_name == b"#size-cells" {
                root_size_cells = read_cell_count(value)?;
            } else if node_eq(current, K230_NODE_SOC) && prop_name == b"#address-cells" {
                soc_address_cells = read_cell_count(value)?;
            } else if node_eq(current, K230_NODE_SOC) && prop_name == b"#size-cells" {
                soc_size_cells = read_cell_count(value)?;
            } else if node_eq(current, K230_NODE_CPUS) && prop_name == b"#address-cells" {
                cpus_address_cells = read_cell_count(value)?;
            } else if node_eq(current, K230_NODE_MEMORY) && prop_name == b"reg" {
                info.memory_range = read_reg_range(value, root_address_cells, root_size_cells);
            } else if node_eq(current, K230_NODE_SERIAL) && prop_name == b"reg" {
                info.console_base = read_reg_range(value, soc_address_cells, soc_size_cells)
                    .map(|range| range.start);
            } else if node_eq(current, K230_NODE_CLINT) && prop_name == b"reg" {
                info.clint_base = read_reg_range(value, soc_address_cells, soc_size_cells)
                    .map(|range| range.start);
            } else if node_eq(current, K230_NODE_CPU) && prop_name == b"reg" {
                if let Some(hart_id) = read_cells(value, cpus_address_cells) {
                    if info.enabled_hart_count < info.enabled_harts.len() {
                        info.enabled_harts[info.enabled_hart_count] = hart_id;
                        info.enabled_hart_count += 1;
                    }
                }
            }

            if is_k230
                && info.memory_range.is_some()
                && info.console_base.is_some()
                && info.clint_base.is_some()
                && info.cpu_num > 0
            {
                break;
            }
        } else if token_eq(token, FDT_NOP) {
        } else if token_eq(token, FDT_END) {
            break;
        } else {
            return None;
        }
    }

    if !is_k230 {
        return None;
    }
    if info.cpu_num == 0 {
        info.cpu_num = 1;
    }
    if info.enabled_hart_count == 0 {
        info.enabled_harts[0] = 0;
        info.enabled_hart_count = 1;
    }
    Some(info)
}

pub fn parse_device_tree(opaque: usize) -> Result<Dtb, ParseDeviceTreeError> {
    let Ok(ptr) = DtbPtr::from_raw(opaque as *mut _) else {
        return Err(ParseDeviceTreeError::Format);
    };
    let dtb = Dtb::from(ptr);
    Ok(dtb)
}

pub fn get_compatible_and_ranges<'de>(node: &Node) -> Option<(StrSeq<'de>, Vec<Range<usize>>)> {
    let compatible = node
        .get_prop("compatible")
        .map(|prop_item| prop_item.deserialize::<StrSeq<'de>>());
    let regs = node.get_prop("reg").map(|prop_item| {
        let reg = prop_item.deserialize::<serde_device_tree::buildin::Reg>();
        reg.iter().map(|range| range.0).collect::<Vec<_>>()
    });
    if let Some(compatible) = compatible {
        if let Some(regs) = regs {
            if regs.is_empty() {
                None
            } else {
                Some((compatible, regs))
            }
        } else {
            None
        }
    } else {
        None
    }
}

pub fn get_compatible_and_range<'de>(node: &Node) -> Option<(StrSeq<'de>, Range<usize>)> {
    let (compatible, regs) = get_compatible_and_ranges(node)?;
    regs.into_iter().next().map(|range| (compatible, range))
}

pub fn get_compatible<'de>(node: &Node) -> Option<StrSeq<'de>> {
    let compatible = node
        .get_prop("compatible")
        .map(|prop_item| prop_item.deserialize::<StrSeq<'de>>());
    if let Some(compatible) = compatible {
        Some(compatible)
    } else {
        None
    }
}

fn classify_k230_node(
    depth: usize,
    parent: K230ProbeNode,
    name: &[u8],
) -> K230ProbeNode {
    if depth == 0 {
        K230_NODE_ROOT
    } else if node_eq(parent, K230_NODE_ROOT) && name == b"cpus" {
        K230_NODE_CPUS
    } else if node_eq(parent, K230_NODE_ROOT) && name == b"soc" {
        K230_NODE_SOC
    } else if node_eq(parent, K230_NODE_ROOT) && name.starts_with(b"memory@") {
        K230_NODE_MEMORY
    } else if node_eq(parent, K230_NODE_CPUS) && name.starts_with(b"cpu@") {
        K230_NODE_CPU
    } else if node_eq(parent, K230_NODE_SOC) && name == b"serial@91400000" {
        K230_NODE_SERIAL
    } else if node_eq(parent, K230_NODE_SOC) && name == b"clint@f04000000" {
        K230_NODE_CLINT
    } else {
        K230_NODE_OTHER
    }
}

unsafe fn read_be32_ptr(ptr: *const u8, offset: usize) -> Option<u32> {
    let bytes = unsafe { core::slice::from_raw_parts(ptr.add(offset), 4) };
    Some(u32::from_be_bytes(bytes.try_into().ok()?))
}

fn read_be32(blob: &[u8], offset: usize) -> Option<u32> {
    let bytes = checked_slice(blob, offset, 4)?;
    Some(u32::from_be_bytes(bytes.try_into().ok()?))
}

fn checked_slice(blob: &[u8], offset: usize, len: usize) -> Option<&[u8]> {
    let end = offset.checked_add(len)?;
    blob.get(offset..end)
}

fn read_struct_name<'a>(structure: &'a [u8], cursor: &mut usize) -> Option<&'a [u8]> {
    let start = *cursor;
    let rest = structure.get(start..)?;
    let len = rest.iter().position(|byte| *byte == 0)?;
    *cursor = align4(start.checked_add(len)?.checked_add(1)?);
    Some(&rest[..len])
}

fn string_at(strings: &[u8], offset: usize) -> Option<&[u8]> {
    let rest = strings.get(offset..)?;
    let len = rest.iter().position(|byte| *byte == 0)?;
    Some(&rest[..len])
}

fn align4(value: usize) -> usize {
    (value + 3) & !3
}

fn string_value_eq(value: &[u8], expected: &[u8]) -> bool {
    value.strip_suffix(&[0])
        .map_or(value == expected, |value| value == expected)
}

fn string_list_contains(value: &[u8], expected: &[u8]) -> bool {
    value
        .split(|byte| *byte == 0)
        .any(|item| item == expected)
}

fn read_cell_count(value: &[u8]) -> Option<usize> {
    Some(read_be32(value, 0)? as usize)
}

fn read_reg_range(value: &[u8], address_cells: usize, size_cells: usize) -> Option<Range<usize>> {
    let base = read_cells(value, address_cells)?;
    let size_offset = address_cells.checked_mul(4)?;
    let size = read_cells(value.get(size_offset..)?, size_cells)?;
    Some(base..base.checked_add(size)?)
}

fn read_cells(value: &[u8], cells: usize) -> Option<usize> {
    if cells > 2 {
        return None;
    }
    let mut result = 0usize;
    for index in 0..cells {
        let offset = index.checked_mul(4)?;
        result = (result << 32) | read_be32(value, offset)? as usize;
    }
    Some(result)
}

#[inline(never)]
fn token_eq(token: u32, expected: u32) -> bool {
    token == expected
}

#[inline(never)]
fn node_eq(node: K230ProbeNode, expected: K230ProbeNode) -> bool {
    node == expected
}

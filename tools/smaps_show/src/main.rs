/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::env;
extern crate getopts;
use getopts::Options;

use std::collections::HashMap;

use regex::RegexBuilder;

use prettytable::{Table, Row, Cell, format};
use prettytable::format::*;

struct VmStruct {
    name:   String,
    start:  u64,
    end:    u64,
    off:    u64,
    perm:   String,
    dev:    String,
    inode:  u64,
    counts: usize,
    value:  HashMap<String, u64>
}
impl VmStruct {
    fn add(&mut self, key: &String, val: u64) {
        let v = self.value.entry(key.clone()).or_insert(0);
        *v += val;
    }
    fn incress_counts(&mut self) {
        self.counts += 1;
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optopt("p", "pid", "parse target pid smaps", "PID");
    opts.optopt("f", "file", "print target file", "FILE");
    opts.optflag("v", "verbose", "verbose mode, not combine");
    opts.optflag("h", "help", "print this help menu");
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => { m }
        Err(_f) => { return print_usage(&program, opts) }
    };
    if matches.opt_present("h") {
        print_usage(&program, opts);
        return;
    }
    if matches.opt_present("p") && matches.opt_present("f") {
        print_usage(&program, opts);
        return;
    }
    let need_combine = if matches.opt_present("v") { false } else { true };

    let pid = match matches.opt_str("p") {
        Some(s) => s.parse().unwrap_or(-1),
        None => -1,
    };
    let mut file_path = match matches.opt_str("f") {
        Some(s) => s,
        None => String::from(""),
    };

    if pid == -1 && &file_path == "" {
        print_usage(&program, opts);
        return;
    }

    if pid != -1 {
        file_path = format!("/proc/{:?}/smaps", pid);
    }

    let smaps_info = read_smaps(&file_path, need_combine);

    if need_combine {
        print_smaps_combined(smaps_info);
    } else {
        print_smaps_verbose(smaps_info);
    }

    std::process::exit(0);
}

fn print_smaps_combined(infos: Vec<VmStruct>) {
    let value_keys = vec![
        ("Size",          "d"),
        ("Rss",           "d"),
        ("Pss",           "d"),
        ("Shared\nClean", "d"),
        ("Shared\nDirty", "d"),
        ("Private\nClean","d"),
        ("Private\nDirty","d"),
        ("Swap",          "d"),
        ("SwapPss",       "d")
    ];
    let info_keys = vec![
        ("Counts",        ""),
        ("Name",          ""),
    ];
    print_smaps_core(infos, &value_keys, &info_keys);
}

fn print_smaps_verbose(infos: Vec<VmStruct>) {
    let value_keys = vec![
        ("Size",          "d"),
        ("Rss",           "d"),
        ("Pss",           "d"),
        ("Shared\nClean", "d"),
        ("Shared\nDirty", "d"),
        ("Private\nClean","d"),
        ("Private\nDirty","d"),
        ("Swap",          "d"),
        ("SwapPss",       "d")
    ];
    let info_keys = vec![
        ("Start",         ""),
        ("End",           ""),
        ("Perm",          ""),
        ("Name",          "")
    ];
    print_smaps_core(infos, &value_keys, &info_keys);
}

fn print_smaps_core(infos: Vec<VmStruct>, value_keys: &Vec<(&str, &str)>, info_keys: &Vec<(&str, &str)>) {
    let mut summary = VmStruct {
        name:   String::from("Summary"),
        start:  0,
        end:    0,
        off:    0,
        perm:   String::from(""),
        dev:    String::from(""),
        inode:  0,
        counts: 0,
        value:  HashMap::from([])
    };

    let mut table = Table::new();
    table.set_format(*format::consts::FORMAT_NO_LINESEP_WITH_TITLE);

    table.set_titles(Row::new(value_keys.into_iter().chain(info_keys.into_iter()).map(|&x| Cell::new(x.0)).collect()));
    for i in infos {
        // make a row
        let mut r = Row::new(value_keys.into_iter().map(|&x| value_to_cell(&i, x.0, x.1)).collect());
        for ik in info_keys {
            r.add_cell(info_to_cell(&i, ik.0, false));
        }
        table.add_row(r);

        // calculate summary
        for (n, v) in i.value {
            summary.add(&n, v);
        }
        summary.counts += i.counts;
    }

    table.add_empty_row();

    // add summary row
    let mut rsum = Row::new(value_keys.into_iter().map(|&x| value_to_cell(&summary, x.0, x.1)).collect());
    for ik in info_keys {
        rsum.add_cell(info_to_cell(&summary, ik.0, true));
    }
    table.add_row(rsum);

    // Print the table to stdout
    table.printstd();
}


fn value_to_cell(i: &VmStruct, k: &str, t: &str) -> Cell {
    if i.value.contains_key(k) {
        match t {
            "x" => Cell::new_align(format!("{:x}", i.value.get(k).unwrap()).as_str(), Alignment::RIGHT),
            "d" => Cell::new_align(format!("{}", i.value.get(k).unwrap()).as_str(), Alignment::RIGHT),
            "s" => Cell::new(format!("{}", i.value.get(k).unwrap()).as_str()),
            _ => Cell::new(""),
        }
    } else {
        Cell::new("")
    }
}

fn info_to_cell(i: &VmStruct, k: &str, is_summary: bool) -> Cell {
    if is_summary {
        match k {
            "Counts" => Cell::new_align(format!("{}", i.counts).as_str(), Alignment::RIGHT),
            "Name" => Cell::new(format!("{}", i.name).as_str()),
            _ => Cell::new("")
        }
    } else {
        match k {
            "Name" => Cell::new(format!("{}", i.name).as_str()),
            "Start" => Cell::new(format!("{:x}", i.start).as_str()),
            "End" => Cell::new(format!("{:x}", i.end).as_str()),
            "Off" => Cell::new(format!("{:x}", i.off).as_str()),
            "Perm" => Cell::new(format!("{}", i.perm).as_str()),
            "Dev" => Cell::new(format!("{}", i.dev).as_str()),
            "Inode" => Cell::new(format!("{}", i.inode).as_str()),
            "Counts" => Cell::new_align(format!("{}", i.counts).as_str(), Alignment::RIGHT),
            _ => Cell::new("")
        }
    }
}

fn read_smaps(file_path: &String, need_combine: bool) -> Vec<VmStruct> {
    let mut output : Vec<VmStruct> = Vec::new();

    // 55de5fa6e000-55de5fad3000 r--p 0011e000 103:03 5908202                   /usr/lib/systemd/systemd
    let regex_head = RegexBuilder::new("^(?P<start>[0-9a-f]+)-(?P<end>[0-9a-f]+)[ \t]+(?P<perm>[^ ]+)[ \t]+(?P<off>[0-9a-f]+)[ \t]+(?P<dev>[0-9a-f:]+)[ \t]+(?P<inode>[0-9a-z]+)[ \t]*(?P<name>.*)")
        .multi_line(true)
        .build()
        .unwrap();
    let regex_val = RegexBuilder::new("^(?P<key>[a-zA-Z_]+):[ \t]+(?P<val>[0-9]+)[ \t]+kB")
        .multi_line(true)
        .build()
        .unwrap();

    let file_context = std::fs::read_to_string(file_path)
        .unwrap();

    let vms: Vec<_> = regex_head
        .find_iter(&file_context)
        .map(|matched| matched.start())
        .chain(std::iter::once(file_context.len()))
        .collect();

    let mut vm_map = HashMap::new();
    for vm in vms.windows(2) {
        let caps = regex_head.captures(&file_context[vm[0]..vm[1]]).unwrap();
        let start = u64::from_str_radix(caps.name("start").unwrap().as_str(), 16).unwrap();
        let end = u64::from_str_radix(caps.name("end").unwrap().as_str(), 16).unwrap();
        let off = u64::from_str_radix(caps.name("off").unwrap().as_str(), 16).unwrap();
        let perm = caps.name("perm").unwrap().as_str();
        let dev = caps.name("dev").unwrap().as_str();
        let inode = u64::from_str_radix(caps.name("inode").unwrap().as_str(), 10).unwrap();

        let mut name = String::from("[anon]");
        if caps.name("name").unwrap().as_str() != "" {
            name = caps.name("name").unwrap().as_str().to_string();
        }

        let value_map: HashMap<String, u64> = regex_val
            .captures_iter(&file_context[vm[0]..vm[1]])
            .map(|cap| {
                let key = cap.get(1).unwrap().as_str().to_owned();
                let value = cap.get(2).unwrap().as_str().parse().unwrap();
                (key.clone().replace("_", "\n"), value)
            })
        .collect();

        if need_combine && vm_map.contains_key(&name) {
            let &idx: &usize = vm_map.get(&name).unwrap();
            for (n, v) in value_map {
                output.get_mut(idx).unwrap().add(&n, v);
            }
            output.get_mut(idx).unwrap().incress_counts();
        } else {
            let mut vms = VmStruct{
                    name: name.clone(),
                    start: start,
                    end: end,
                    off: off,
                    perm: perm.to_string(),
                    dev: dev.to_string(),
                    inode: inode,
                    counts: 1,
                    value: HashMap::from([])};

            for (n, v) in value_map {
                vms.add(&n, v);
            }
            output.push(vms);
            if need_combine {
                vm_map.insert(name.clone(), output.len() - 1);
            }
        }
    }
    output
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options] PID/FILE ", program);
    print!("{}", opts.usage(&brief));
}

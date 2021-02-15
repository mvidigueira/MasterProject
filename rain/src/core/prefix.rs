use serde::Serialize;
use std::collections::HashMap;
use std::hash::Hash;
use std::num::Wrapping;

#[derive(Clone, PartialEq, Eq)]
pub struct SystemConfig<I> {
    mapping: Vec<(Prefix, Vec<I>)>,
}

impl<I> SystemConfig<I>
where
    I: Eq + Hash,
{
    pub fn new(mut mapping: Vec<(Prefix, Vec<I>)>) -> Self {
        mapping.sort_by(|x, y| x.0.cmp(&y.0));
        Self { mapping }
    }

    pub fn assignments<K: Serialize + Clone>(
        &self,
        records: &Vec<K>,
    ) -> HashMap<&I, Vec<K>> {
        assignments(&self.mapping, records)
    }

    pub fn get_group_covering<K: Serialize + Clone>(
        &self,
        record: &K,
    ) -> Vec<&I> {
        covering(&self.mapping, record)
    }
}

impl<I> SystemConfig<I>
where
    I: Eq + Hash + Clone,
{
    pub fn from_inverse(mapping: Vec<(I, Vec<Prefix>)>) -> Self {
        let mut prefix_map = HashMap::<Prefix, Vec<I>>::new();
        for (corenode, ps) in mapping.iter() {
            for p in ps {
                let e = prefix_map.entry(p.clone()).or_insert(vec![]);
                e.push(corenode.clone());
            }
        }

        // for (node_info, local_prefixes) in mapping.drain(..) {
        //     for prefix in local_prefixes {
        //         let e = prefix_map.entry(prefix.clone()).or_insert(vec![]);
        //         e.push(node_info.clone());
        //     }
        // }
        let prefix_list: Vec<(Prefix, Vec<I>)> =
            prefix_map.drain().collect();
        SystemConfig::new(prefix_list)

    }
}

// E.g.: returns all corenode-prefix assignments, covering all records.
pub fn assignments<'a, I: Eq + Hash, K: Serialize + Clone>(
    prefix_assignments_list: &'a Vec<(Prefix, Vec<I>)>,
    records: &Vec<K>,
) -> HashMap<&'a I, Vec<K>> {
    let mut m: HashMap<&'a I, Vec<K>> = HashMap::new();

    for r_id in records.iter() {
        let infos = covering(prefix_assignments_list, r_id);
        for i in infos {
            let e = m.entry(i).or_insert(Vec::new());
            e.push(r_id.clone());
        }
    }

    m
}

// E.g. returns all corenodes covering that record
pub fn covering<'a, I: PartialEq, K: Serialize>(
    prefix_assignments_list: &'a Vec<(Prefix, Vec<I>)>,
    r_id: &K,
) -> Vec<&'a I> {
    let h = Prefix::new(drop::crypto::hash(r_id).unwrap().as_ref().to_vec(), 0);
    let mut ret: Vec<&I> = vec![];
    for (p, v) in prefix_assignments_list.iter() {
        if p.includes(&h) || h.includes(&p) {
            for di in v {
                if !ret.contains(&di) {
                    ret.push(di);
                }
            }
        }
    }

    ret
}

// Empty prefix includes all
#[derive(PartialEq, Eq, Clone, Debug, Hash)]
pub struct Prefix {
    key: Vec<u8>,
    remainder: u8, // total length of prefix = [key.size()-1] * 8 + remainder bits
}

impl Prefix {
    pub fn new(key: Vec<u8>, remainder: u8) -> Self {
        Prefix { key, remainder }
    }

    pub fn bit_len(&self) -> usize {
        (self.key.len() - 1) * 8 + self.remainder as usize
    }

    pub fn bit(&self, n: usize) -> bool {
        if n > self.bit_len() {
            panic!("Prefix too short");
        }

        (self.key[n / 8] & (1 << 7 - n % 8)) > 0
    }

    pub fn increment(&mut self) {
        let s = self.key.len();
        if s == 0 {
            // Cannot increment empty prefix
            return;
        }
        let increment = if self.remainder == 0 {
            1u8
        } else {
            2u8.pow(8 - self.remainder as u32)
        };

        self.key[s - 1] = (Wrapping(self.key[s - 1]) + Wrapping(increment)).0;

        for i in (1..s).rev() {
            if self.key[i] == 0 {
                self.key[i - 1] = (Wrapping(self.key[i - 1]) + Wrapping(1)).0;
            } else {
                break;
            }
        }
    }

    pub fn set_length_in_bits(&mut self, length: usize) {
        let mut s = length / 8;
        let remainder = (length % 8) as u8;
        if remainder > 0 {
            s += 1;
        }
        self.key.resize(s, 0);
        if s > 0 && remainder > 0 {
            self.key[s - 1] &= u8::MAX << (8 - remainder);
        }
        self.remainder = remainder;
    }

    pub fn includes(&self, other: &Self) -> bool {
        // Compare full bytes

        let mut len_a = self.key.len() * 8;
        if self.remainder > 0 {
            len_a = len_a - 8 + self.remainder as usize;
        }

        let mut len_b = other.key.len() * 8;
        if other.remainder > 0 {
            len_b = len_b - 8 + other.remainder as usize;
        }

        let min = std::cmp::min(len_a, len_b);
        let full_byte_count = min / 8;
        let min_remainder = min % 8;

        if full_byte_count > 0 {
            match self.key[0..full_byte_count]
                .cmp(&other.key[0..full_byte_count])
            {
                std::cmp::Ordering::Equal => (),
                _ => return false,
            }
        }

        // Compare last incomplete byte
        if min_remainder > 0 {
            let (byte_a, byte_b) =
                (self.key[full_byte_count], other.key[full_byte_count]);
            let byte_a = (byte_a >> (8 - min_remainder)) << (8 - min_remainder);
            let byte_b = (byte_b >> (8 - min_remainder)) << (8 - min_remainder);
            match byte_a.cmp(&byte_b) {
                std::cmp::Ordering::Equal => (),
                _ => return false,
            }
        }

        return len_a <= len_b;
    }
}

pub fn set_bit(v: &mut Vec<u8>, index: usize, value: bool) {
    if value {
        let sub_index: u8 = 1 << (7 - (index % 8));
        v[(index / 8) as usize] |= sub_index;
    } else {
        let sub_index: u8 = 1 << (7 - (index % 8));
        v[(index / 8) as usize] &= !sub_index;
    }
}

impl From<&str> for Prefix {
    fn from(s: &str) -> Self {
        if s.len() > 256 {
            panic!("Prefix must have length between 0 and 256");
        }

        let mut num_bytes = s.len() / 8;
        let remainder = (s.len() % 8) as u8;
        if remainder > 0 {
            num_bytes += 1
        }

        let mut v: Vec<u8> = vec![0; num_bytes];
        for (i, c) in s.chars().enumerate() {
            if c == '0' {
                ()
            } else if c == '1' {
                set_bit(&mut v, i, true);
            } else {
                panic!("String must only contain chars 0 and 1");
            }
        }

        Prefix::new(v, remainder)
    }
}

impl Ord for Prefix {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Compare full bytes
        let full_byte_count = std::cmp::min(self.key.len(), other.key.len());
        if full_byte_count > 0 {
            match self.key[0..full_byte_count]
                .cmp(&other.key[0..full_byte_count])
            {
                std::cmp::Ordering::Equal => (),
                other => return other,
            }
        }

        // Compare last incomplete byte
        let min_remainder = std::cmp::min(self.remainder, other.remainder);
        if min_remainder > 0 {
            let (byte_a, byte_b) =
                (self.key[full_byte_count], other.key[full_byte_count]);
            let byte_a = (byte_a >> (8 - min_remainder)) << (8 - min_remainder);
            let byte_b = (byte_b >> (8 - min_remainder)) << (8 - min_remainder);
            if full_byte_count > 0 {
                match byte_a.cmp(&byte_b) {
                    std::cmp::Ordering::Equal => (),
                    other => return other,
                }
            }
        }

        // Compare bitlength
        self.remainder.cmp(&other.remainder)
    }
}

impl PartialOrd for Prefix {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

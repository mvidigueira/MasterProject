use drop::crypto::Digest;

// bits: 0 -> most significant, 255 -> least significant
#[inline]
pub fn bit(arr: &[u8; 32], index: u8) -> bool {
    let byte = arr[(index / 8) as usize];
    let sub_index: u8 = 1 << (7 - (index % 8));
    (byte & sub_index) > 0
}

#[inline]
pub fn set_bit(arr: &mut [u8; 32], index: u8, value: bool) {
    if value {
        let sub_index: u8 = 1 << (7 - (index % 8));
        arr[(index / 8) as usize] |= sub_index;
    } else {
        let sub_index: u8 = 1 << (7 - (index % 8));
        arr[(index / 8) as usize] &= !sub_index;
    }
}

pub fn closest<'a>(
    sorted: &'a Vec<Digest>,
    key_d: &[u8; 32],
) -> &'a Digest {
    let r = sorted
        .binary_search_by_key(key_d, |x| *x.as_ref());

    match r {
        Ok(i) => &sorted[i],
        Err(i) => {
            if sorted.len() <= i {
                &sorted.last().unwrap()
            } else if i == 0 {
                &sorted.last().unwrap()
            } else {
                &sorted[i-1]
            }
        }
    }
}

pub fn leading_bits_in_common(a: &[u8; 32], b: &[u8; 32]) -> usize {
    let mut count = 0;
    for i in 0..=255 {
        if bit(a, i) == bit(b, i) {
            count +=1 ;
        } else {
            break;
        }
    }
    count
}

pub fn get_is_close_fn(my_d: Digest, mut d_list: Vec<Digest>) -> impl Fn([u8; 32], usize) -> bool {
    d_list.sort_by_key(|x| *x.as_ref());

    move |path: [u8; 32], up_to_bit: usize| {
        let closest_d = closest(&d_list, &path);
        let closest_score = std::cmp::min(leading_bits_in_common(closest_d.as_ref(), &path), up_to_bit);

        let me_score = std::cmp::min(leading_bits_in_common(my_d.as_ref(), &path), up_to_bit);

        if me_score == closest_score {
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bit() {
        let u = &mut [0 as u8; 32];
        u[0] = 0x88;
        u[1] = 0x55;

        assert_eq!(bit(u, 0), true);
        assert_eq!(bit(u, 1), false);
        assert_eq!(bit(u, 8), false);
        assert_eq!(bit(u, 9), true);
    }

    #[test]
    fn test_set_bit() {
        let u = &mut [0 as u8; 32];
        u[0] = 0x88;
        u[1] = 0x55;
        set_bit(u, 2, true);
        set_bit(u, 0, false);
        set_bit(u, 8, true);

        assert_eq!(bit(u, 0), false);
        assert_eq!(bit(u, 1), false);
        assert_eq!(bit(u, 2), true);
        assert_eq!(bit(u, 3), false);
        assert_eq!(bit(u, 4), true);
        assert_eq!(bit(u, 5), false);
        assert_eq!(bit(u, 6), false);
        assert_eq!(bit(u, 7), false);
        assert_eq!(bit(u, 8), true);
    }

    #[test]
    fn test_clear_bits_to_end_1() {
        let u = &mut [0 as u8; 32];
        u[0] = 0x88;
        u[1] = 0x55;
        u[2] = 0xff;
        u[31] = 0xff;
        clear_bits_to_end(u, 5);

        assert_eq!(u[0], 0x88);
        assert_eq!(u[1], 0x00);
        assert_eq!(u[2], 0x00);
        assert_eq!(u[31], 0x00);
    }

    #[test]
    fn test_clear_bits_to_end_2() {
        let u = &mut [0xff as u8; 32];
        clear_bits_to_end(u, 252);

        assert_eq!(u[0], 0xff);
        assert_eq!(u[1], 0xff);
        assert_eq!(u[2], 0xff);
        assert_eq!(u[31], 0xf0);
    }

}
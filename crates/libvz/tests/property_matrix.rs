use std::collections::BTreeMap;
use std::io::Cursor;

use proptest::prelude::*;
use libvz::{
    CODEC_LZ4, CODEC_NONE, CODEC_ZSTD, ClusterHeader, VzError, VzReader, VzWriter, VzWriterConfig,
    build_cluster_from_body, encode_rs_gf256_stripe, parse_parity_cluster_body,
    recover_rs_gf256_stripe, validate_cluster,
};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn prop_random_archive_roundtrip(
        entries in prop::collection::vec(
            (
                prop::collection::vec("[a-z]{1,6}", 1..=4),
                prop::collection::vec(any::<u8>(), 0..=4096),
            ),
            1..=40
        ),
        codec_choice in 0u8..=2,
        leaf_cap in 2usize..=16,
    ) {
        let codec = match codec_choice {
            0 => CODEC_NONE,
            1 => CODEC_LZ4,
            _ => CODEC_ZSTD,
        };
        let mut expected: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        for (segs, data) in entries {
            let path = format!("/{}", segs.join("/"));
            // Avoid directory/file path prefix conflicts in random generation
            if !expected.keys().any(|k| k.starts_with(&format!("{path}/")) || path.starts_with(&format!("{k}/"))) {
                expected.insert(path, data);
            }
        }

        let cfg = VzWriterConfig {
            default_codec: codec,
            max_leaf_entries: leaf_cap,
            max_route_entries: 4,
            target_cluster_size: 8192,
            multi_cluster_threshold: 8192,
            ..Default::default()
        };
        let mut w = VzWriter::new(Cursor::new(Vec::new()), cfg).unwrap();
        for (path, data) in &expected {
            w.add_file(path, data).unwrap();
        }
        let archive = w.finish().unwrap().into_inner();
        let r = VzReader::open(archive).unwrap();

        for (path, data) in &expected {
            let st = r.stat(path).unwrap();
            prop_assert_eq!(st.size, data.len() as u64);
            let got = r.read_file(path).unwrap();
            prop_assert_eq!(&got, data);
        }
    }

    #[test]
    fn prop_random_rs_gf256_erasure_recovery(
        k in 1u16..=16,
        m in 1u16..=6,
        seed in any::<u64>(),
    ) {
        // Generate K valid variable-length clusters.
        let mut clusters: Vec<Vec<u8>> = Vec::with_capacity(k as usize);
        let mut offsets: Vec<u64> = Vec::with_capacity(k as usize);
        let mut off = 65_536u64;
        let mut prev_len = 0u64;
        for j in 0..k {
            let body_len = 16 + (((seed.wrapping_mul(6364136223846793005).wrapping_add(j as u64 * 131)) % 512) as usize);
            let mut body = vec![0xEC]; // TAG_VOID
            let mut lbuf = [0u8; 8];
            let lw = libvz::write_levint(&mut lbuf, body_len as u64).unwrap();
            body.extend_from_slice(&lbuf[..lw]);
            for i in 0..body_len {
                body.push(((seed >> ((i % 8) * 8)) as u8).wrapping_add(i as u8).wrapping_add(j as u8));
            }
            let c = build_cluster_from_body(&body, prev_len, j as u64).unwrap();
            prev_len = c.len() as u64;
            offsets.push(off);
            off += prev_len;
            clusters.push(c);
        }

        let refs: Vec<&[u8]> = clusters.iter().map(Vec::as_slice).collect();
        let max_len = clusters.iter().map(Vec::len).max().unwrap();
        let (parities, _) = encode_rs_gf256_stripe(&refs, &offsets, 0, m, k as u64, prev_len).unwrap();

        // Pick deterministic random subset of up to M total erasures across data + parity.
        let total = (k + m) as usize;
        let mut indices: Vec<usize> = (0..total).collect();
        let mut rng = seed ^ 0x9E37_79B9_7F4A_7C15;
        for i in (1..total).rev() {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let j = (rng as usize) % (i + 1);
            indices.swap(i, j);
        }
        let erase_count = ((rng as usize) % (m as usize)) + 1;
        let erased = &indices[..erase_count];

        let mut data_slots: Vec<Option<Vec<u8>>> = clusters.iter().map(|c| Some(c.clone())).collect();
        let mut parity_slots: Vec<Option<(u16, Vec<u8>)>> = Vec::with_capacity(m as usize);
        for (p_idx, p_cluster) in parities.iter().enumerate() {
            let (_, body, _) = validate_cluster(p_cluster).unwrap();
            let (manifest, _, payload) = parse_parity_cluster_body(body).unwrap().unwrap();
            parity_slots.push(Some((manifest.parity_index, payload.to_vec())));
            let _ = p_idx;
        }

        for &idx in erased {
            if idx < k as usize {
                data_slots[idx] = None;
            } else {
                parity_slots[idx - k as usize] = None;
            }
        }

        let _ = recover_rs_gf256_stripe(&mut data_slots, &parity_slots, k as usize, m as usize, max_len).unwrap();
        for (j, slot) in data_slots.iter().enumerate() {
            prop_assert_eq!(slot.as_ref().unwrap(), &clusters[j]);
            let hdr = ClusterHeader::from_bytes(slot.as_ref().unwrap()).unwrap();
            prop_assert_eq!(hdr.cluster_seq, j as u64);
        }

        // Also confirm M+1 erasures fails when K + M >= M + 1.
        if total >= (m as usize + 1) {
            let mut too_many_data: Vec<Option<Vec<u8>>> = clusters.iter().map(|c| Some(c.clone())).collect();
            let mut too_many_parity = parity_slots.clone();
            for &idx in &indices[..=(m as usize)] {
                if idx < k as usize {
                    too_many_data[idx] = None;
                } else {
                    too_many_parity[idx - k as usize] = None;
                }
            }
            let res = recover_rs_gf256_stripe(&mut too_many_data, &too_many_parity, k as usize, m as usize, max_len);
            prop_assert_eq!(res, Err(VzError::CorruptUnrecoverable));
        }
    }
}

// SPDX-License-Identifier: Apache-2.0
//! The default, **dependency-free** local vector-store backend (C5.2).
//!
//! It is a thin namespaced wrapper over the same brute-force cosine nearest-neighbor scan
//! that [`crustcore_index::embed::VectorMemory`] performs, reusing
//! [`crustcore_index::embed::cosine`] verbatim (no re-implemented ranking). It preserves
//! `VectorMemory`'s query semantics exactly: only **positively-similar** hits, sorted by
//! descending score with **insertion-order tie-breaks** (deterministic). A `floor` is an
//! additional lower bound on top of the positive-similarity filter.
//!
//! Persistence (C5-persist, behind the off-by-default `persist` feature) is a
//! dependency-free, versioned, bounded, panic-free snapshot — same discipline as
//! `crustcore-index`'s [`MemoryStore`](crustcore_index::MemoryStore) snapshot and the
//! event-log/secret-vault frame formats: a magic header, a version byte, length-prefixed
//! little-endian fields, every count/length bounded by a MAX **before** allocation, and a
//! fail-closed decoder that never panics on hostile bytes. See [`LocalVectorStore::save`]
//! / [`LocalVectorStore::load`]. The default (no-feature) path is purely in-memory and
//! dependency-free.

use std::collections::BTreeMap;

use crustcore_index::embed::cosine;

use super::{ChunkId, ChunkMeta, VectorStore, DEFAULT_NAMESPACE};

/// One stored chunk: its embedding, metadata, and a monotonic insertion sequence used
/// for deterministic tie-breaking (mirrors `VectorMemory`'s insertion-order ties).
#[derive(Debug, Clone)]
struct Stored {
    embedding: Vec<f32>,
    meta: ChunkMeta,
    seq: u64,
}

/// The dependency-free default backend. Chunks are partitioned by namespace; within a
/// namespace an upsert replaces by [`ChunkId`] (idempotent).
#[derive(Debug)]
pub struct LocalVectorStore {
    namespaces: BTreeMap<String, BTreeMap<ChunkId, Stored>>,
    namespace: String,
    next_seq: u64,
}

impl Default for LocalVectorStore {
    fn default() -> Self {
        LocalVectorStore::new()
    }
}

impl LocalVectorStore {
    /// An empty store scoped to the default namespace.
    #[must_use]
    pub fn new() -> Self {
        LocalVectorStore {
            namespaces: BTreeMap::new(),
            namespace: DEFAULT_NAMESPACE.to_string(),
            next_seq: 0,
        }
    }

    fn active(&self) -> Option<&BTreeMap<ChunkId, Stored>> {
        self.namespaces.get(&self.namespace)
    }
}

// ---------------------------------------------------------------------------
// Persistent snapshot (C5-persist) — dependency-free, versioned, bounded, panic-free
// ---------------------------------------------------------------------------
//
// Mirrors `crustcore_index::MemoryStore`'s snapshot discipline exactly (own magic
// "CCRG"): a magic header, a version byte, length-prefixed little-endian fields, every
// count/length pre-checked against a MAX before any allocation, and a decoder that
// fail-closes on bad magic / unknown version / truncation and never panics on hostile
// bytes. The stored entries are untrusted, **non-secret** vectors + provenance metadata
// (invariant 7), so the snapshot is written in the clear (contrast the encrypted secret
// vault). f32 embeddings are encoded as raw little-endian IEEE-754 bytes; `cosine` already
// sanitizes non-finite values at query time, so a NaN/inf that round-trips cannot poison
// ranking.
#[cfg(feature = "persist")]
mod persist {
    use std::collections::BTreeMap;

    use crustcore_index::MemorySource;

    use super::{LocalVectorStore, Stored};
    use crate::store::{ByteSpan, ChunkId, ChunkMeta, DEFAULT_NAMESPACE};

    /// Magic for a local vector-store snapshot (`CrustCore Rag`).
    pub const RAG_MAGIC: [u8; 4] = *b"CCRG";
    /// Snapshot format version (bump on any layout change; an old reader rejects a newer
    /// file rather than misreading it).
    pub const RAG_VERSION: u8 = 1;

    /// Cap on namespaces restored from a snapshot (bounded; invariant 11).
    pub const MAX_NAMESPACES: usize = 4 * 1024;
    /// Cap on entries (chunks) restored per namespace (bounded — a corrupt/hostile file
    /// cannot blow up memory).
    pub const MAX_ENTRIES_PER_NS: usize = 256 * 1024;
    /// Cap on an embedding's dimension (bounded — a tiny file claiming a huge dim cannot
    /// amplify into a large allocation).
    pub const MAX_EMBED_DIM: usize = 64 * 1024;
    /// Cap on a single string/byte field (namespace name, chunk id, path, symbol).
    pub const MAX_FIELD_BYTES: usize = 64 * 1024;

    /// Why a vector-store snapshot could not be saved or loaded.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum SnapshotError {
        /// An I/O error reading/writing the file (bounded message).
        Io(String),
        /// The file is not a vector-store snapshot (bad magic / truncated header).
        BadFormat,
        /// An unsupported snapshot version.
        BadVersion(u8),
        /// The contents are malformed or exceed a bound (corrupt / hostile file).
        BadContents,
    }

    impl core::fmt::Display for SnapshotError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self {
                SnapshotError::Io(e) => write!(f, "vector-store snapshot io: {e}"),
                SnapshotError::BadFormat => write!(f, "not a vector-store snapshot"),
                SnapshotError::BadVersion(v) => {
                    write!(f, "unsupported vector-store snapshot version {v}")
                }
                SnapshotError::BadContents => write!(f, "malformed vector-store snapshot"),
            }
        }
    }

    impl std::error::Error for SnapshotError {}

    impl LocalVectorStore {
        /// Writes the whole store (all namespaces) to `path` as a versioned, self-describing
        /// snapshot, so a vector index **survives a restart** (`TODO(C5-persist)` realized).
        /// The format is dependency-free (like the event-log frame, the secret vault, and
        /// `crustcore-index`'s memory snapshot):
        ///
        /// ```text
        /// magic | version | next_seq | active_namespace | ns_count |
        ///   [ ns_name | entry_count | [ chunk_id | seq | dim | embedding(f32 LE)… |
        ///       path | symbol_present | symbol? | source | redact_required ]… ]…
        /// ```
        ///
        /// every string/byte field length-prefixed little-endian. The stored vectors and
        /// metadata are untrusted, **non-secret** prior observations (invariant 7), so the
        /// snapshot is written in the clear.
        ///
        /// # Errors
        /// [`SnapshotError::Io`] if the file cannot be written; [`SnapshotError::BadContents`]
        /// only if a length somehow exceeds `u32::MAX` (not reachable for in-bound data).
        pub fn save(&self, path: &std::path::Path) -> Result<(), SnapshotError> {
            let mut buf = Vec::new();
            buf.extend_from_slice(&RAG_MAGIC);
            buf.push(RAG_VERSION);
            buf.extend_from_slice(&self.next_seq.to_le_bytes());
            write_field(&mut buf, self.namespace.as_bytes())?;
            let ns_count =
                u32::try_from(self.namespaces.len()).map_err(|_| SnapshotError::BadContents)?;
            buf.extend_from_slice(&ns_count.to_le_bytes());
            for (ns_name, entries) in &self.namespaces {
                write_field(&mut buf, ns_name.as_bytes())?;
                let entry_count =
                    u32::try_from(entries.len()).map_err(|_| SnapshotError::BadContents)?;
                buf.extend_from_slice(&entry_count.to_le_bytes());
                for (id, stored) in entries {
                    write_field(&mut buf, id.as_str().as_bytes())?;
                    buf.extend_from_slice(&stored.seq.to_le_bytes());
                    write_embedding(&mut buf, &stored.embedding)?;
                    write_meta(&mut buf, &stored.meta)?;
                }
            }
            std::fs::write(path, &buf).map_err(|e| SnapshotError::Io(e.to_string()))
        }

        /// Reloads a store from a snapshot written by [`save`](Self::save). **Fails closed**
        /// on a bad magic/version and decodes **panic-free and bounded**: a corrupt or
        /// hostile file yields a [`SnapshotError`], never a panic or an unbounded allocation
        /// — every count (namespaces, entries, embedding dim) and field length is checked
        /// against its MAX before anything is read, and preallocations are capped, so a tiny
        /// file claiming huge counts cannot amplify into a large allocation.
        ///
        /// # Errors
        /// [`SnapshotError`] on an I/O failure, a bad header, or malformed/over-cap contents.
        pub fn load(path: &std::path::Path) -> Result<LocalVectorStore, SnapshotError> {
            let bytes = std::fs::read(path).map_err(|e| SnapshotError::Io(e.to_string()))?;
            decode_snapshot(&bytes)
        }
    }

    /// A bounded, panic-free reader over a snapshot's bytes.
    struct Reader<'a> {
        bytes: &'a [u8],
        pos: usize,
    }

    impl<'a> Reader<'a> {
        fn new(bytes: &'a [u8]) -> Self {
            Reader { bytes, pos: 0 }
        }

        fn take(&mut self, n: usize) -> Option<&'a [u8]> {
            let end = self.pos.checked_add(n)?;
            let slice = self.bytes.get(self.pos..end)?;
            self.pos = end;
            Some(slice)
        }

        fn read_u8(&mut self) -> Option<u8> {
            self.take(1).map(|b| b[0])
        }

        fn read_u32(&mut self) -> Option<u32> {
            let b = self.take(4)?;
            Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        }

        fn read_u64(&mut self) -> Option<u64> {
            let b = self.take(8)?;
            let mut arr = [0u8; 8];
            arr.copy_from_slice(b);
            Some(u64::from_le_bytes(arr))
        }

        /// A length-prefixed byte field, bounded to [`MAX_FIELD_BYTES`] before reading.
        fn read_field(&mut self) -> Result<String, SnapshotError> {
            let len = self.read_u32().ok_or(SnapshotError::BadContents)? as usize;
            if len > MAX_FIELD_BYTES {
                return Err(SnapshotError::BadContents);
            }
            let raw = self.take(len).ok_or(SnapshotError::BadContents)?;
            Ok(String::from_utf8_lossy(raw).into_owned())
        }
    }

    fn write_field(buf: &mut Vec<u8>, data: &[u8]) -> Result<(), SnapshotError> {
        let len = u32::try_from(data.len()).map_err(|_| SnapshotError::BadContents)?;
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(data);
        Ok(())
    }

    fn write_embedding(buf: &mut Vec<u8>, embedding: &[f32]) -> Result<(), SnapshotError> {
        let dim = u32::try_from(embedding.len()).map_err(|_| SnapshotError::BadContents)?;
        buf.extend_from_slice(&dim.to_le_bytes());
        for v in embedding {
            buf.extend_from_slice(&v.to_le_bytes());
        }
        Ok(())
    }

    fn write_meta(buf: &mut Vec<u8>, meta: &ChunkMeta) -> Result<(), SnapshotError> {
        write_field(buf, meta.path.as_bytes())?;
        let start = u32::try_from(meta.byte_span.start).map_err(|_| SnapshotError::BadContents)?;
        let end = u32::try_from(meta.byte_span.end).map_err(|_| SnapshotError::BadContents)?;
        buf.extend_from_slice(&start.to_le_bytes());
        buf.extend_from_slice(&end.to_le_bytes());
        match &meta.symbol {
            Some(sym) => {
                buf.push(1);
                write_field(buf, sym.as_bytes())?;
            }
            None => buf.push(0),
        }
        buf.push(source_to_u8(meta.source));
        buf.push(u8::from(meta.redact_required));
        Ok(())
    }

    fn decode_snapshot(bytes: &[u8]) -> Result<LocalVectorStore, SnapshotError> {
        let mut r = Reader::new(bytes);
        if r.take(4).ok_or(SnapshotError::BadFormat)? != RAG_MAGIC {
            return Err(SnapshotError::BadFormat);
        }
        let version = r.read_u8().ok_or(SnapshotError::BadFormat)?;
        if version != RAG_VERSION {
            return Err(SnapshotError::BadVersion(version));
        }
        let next_seq = r.read_u64().ok_or(SnapshotError::BadContents)?;
        let active_namespace = r.read_field()?;
        let ns_count = r.read_u32().ok_or(SnapshotError::BadContents)? as usize;
        if ns_count > MAX_NAMESPACES {
            return Err(SnapshotError::BadContents);
        }
        let mut namespaces: BTreeMap<String, BTreeMap<ChunkId, Stored>> = BTreeMap::new();
        for _ in 0..ns_count {
            let ns_name = r.read_field()?;
            let entry_count = r.read_u32().ok_or(SnapshotError::BadContents)? as usize;
            if entry_count > MAX_ENTRIES_PER_NS {
                return Err(SnapshotError::BadContents);
            }
            let mut entries: BTreeMap<ChunkId, Stored> = BTreeMap::new();
            for _ in 0..entry_count {
                let id = ChunkId::new(r.read_field()?);
                let seq = r.read_u64().ok_or(SnapshotError::BadContents)?;
                let embedding = read_embedding(&mut r)?;
                let meta = read_meta(&mut r)?;
                entries.insert(
                    id,
                    Stored {
                        embedding,
                        meta,
                        seq,
                    },
                );
            }
            namespaces.insert(ns_name, entries);
        }
        Ok(LocalVectorStore {
            namespaces,
            namespace: if active_namespace.is_empty() {
                DEFAULT_NAMESPACE.to_string()
            } else {
                active_namespace
            },
            next_seq,
        })
    }

    fn read_embedding(r: &mut Reader<'_>) -> Result<Vec<f32>, SnapshotError> {
        let dim = r.read_u32().ok_or(SnapshotError::BadContents)? as usize;
        // Pre-check the claimed dimension before allocating: a tiny file claiming a huge dim
        // is rejected rather than amplifying into a large allocation.
        if dim > MAX_EMBED_DIM {
            return Err(SnapshotError::BadContents);
        }
        // Cap the preallocation; the Vec grows as real values are decoded (and decoding fails
        // cleanly when the bytes run out).
        let mut embedding = Vec::with_capacity(dim.min(1024));
        for _ in 0..dim {
            let b = r.take(4).ok_or(SnapshotError::BadContents)?;
            embedding.push(f32::from_le_bytes([b[0], b[1], b[2], b[3]]));
        }
        Ok(embedding)
    }

    fn read_meta(r: &mut Reader<'_>) -> Result<ChunkMeta, SnapshotError> {
        let path = r.read_field()?;
        let start = r.read_u32().ok_or(SnapshotError::BadContents)? as usize;
        let end = r.read_u32().ok_or(SnapshotError::BadContents)? as usize;
        let symbol = match r.read_u8().ok_or(SnapshotError::BadContents)? {
            0 => None,
            1 => Some(r.read_field()?),
            _ => return Err(SnapshotError::BadContents),
        };
        let source = u8_to_source(r.read_u8().ok_or(SnapshotError::BadContents)?)
            .ok_or(SnapshotError::BadContents)?;
        let redact_required = match r.read_u8().ok_or(SnapshotError::BadContents)? {
            0 => false,
            1 => true,
            _ => return Err(SnapshotError::BadContents),
        };
        // ByteSpan::new clamps end >= start, so an inverted span in a hostile file is
        // normalized rather than panicking.
        let mut meta = ChunkMeta::new(path, ByteSpan::new(start, end), source);
        meta.symbol = symbol;
        meta.redact_required = redact_required;
        Ok(meta)
    }

    fn source_to_u8(s: MemorySource) -> u8 {
        match s {
            MemorySource::RepoFile => 0,
            MemorySource::ToolObservation => 1,
            MemorySource::PriorRun => 2,
            MemorySource::UserNote => 3,
        }
    }

    fn u8_to_source(b: u8) -> Option<MemorySource> {
        match b {
            0 => Some(MemorySource::RepoFile),
            1 => Some(MemorySource::ToolObservation),
            2 => Some(MemorySource::PriorRun),
            3 => Some(MemorySource::UserNote),
            _ => None,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crustcore_index::embed::{Embedder, HashEmbedder};

        use crate::store::VectorStore;

        fn meta(path: &str) -> ChunkMeta {
            ChunkMeta::new(path, ByteSpan::new(3, 17), MemorySource::RepoFile)
        }

        fn populated() -> LocalVectorStore {
            let e = HashEmbedder;
            let mut store = LocalVectorStore::new();
            store.set_namespace("ns1");
            store.upsert(vec![
                (ChunkId::new("a"), e.embed("alpha beta gamma"), meta("a.rs")),
                (
                    ChunkId::new("b"),
                    e.embed("delta epsilon"),
                    meta("b.rs").with_symbol("fn_b"),
                ),
            ]);
            store.set_namespace("ns2");
            store.upsert(vec![(ChunkId::new("c"), e.embed("zeta"), meta("c.rs"))]);
            store.set_namespace("ns1");
            store
        }

        #[test]
        fn snapshot_round_trips() {
            let store = populated();
            let path = std::env::temp_dir().join("cc_rag_roundtrip.ccrg");
            store.save(&path).unwrap();
            let loaded = LocalVectorStore::load(&path).unwrap();

            // Active namespace, seq counter, and per-namespace contents all survive.
            assert_eq!(loaded.namespace(), "ns1");
            assert_eq!(loaded.next_seq, store.next_seq);
            assert_eq!(
                loaded.namespaces.keys().collect::<Vec<_>>(),
                store.namespaces.keys().collect::<Vec<_>>()
            );
            // Every stored chunk (id, embedding, meta, seq) round-trips exactly.
            for (ns, orig) in &store.namespaces {
                let got = loaded.namespaces.get(ns).expect("namespace present");
                assert_eq!(got.len(), orig.len());
                for (id, s) in orig {
                    let g = got.get(id).expect("chunk present");
                    assert_eq!(g.seq, s.seq);
                    assert_eq!(g.embedding, s.embedding);
                    assert_eq!(g.meta, s.meta);
                }
            }

            // Query semantics are preserved: a "ns1" query still ranks its docs; "ns2" is
            // a separate partition.
            let e = HashEmbedder;
            let q = e.embed("alpha beta");
            let mut reloaded = loaded;
            reloaded.set_namespace("ns1");
            assert!(reloaded
                .nearest(&q, 5, 0.0)
                .iter()
                .any(|(id, _, _)| id.0 == "a"));
            reloaded.set_namespace("ns2");
            assert_eq!(reloaded.len(), 1);
            let _ = std::fs::remove_file(&path);
        }

        #[test]
        fn empty_snapshot_round_trips() {
            let store = LocalVectorStore::new();
            let path = std::env::temp_dir().join("cc_rag_empty.ccrg");
            store.save(&path).unwrap();
            let loaded = LocalVectorStore::load(&path).unwrap();
            assert_eq!(loaded.namespace(), DEFAULT_NAMESPACE);
            assert!(loaded.is_empty());
            let _ = std::fs::remove_file(&path);
        }

        #[test]
        fn bad_magic_is_rejected() {
            assert!(matches!(
                decode_snapshot(b"XXXX\x01"),
                Err(SnapshotError::BadFormat)
            ));
            // Empty input is not a snapshot.
            assert!(matches!(
                decode_snapshot(b""),
                Err(SnapshotError::BadFormat)
            ));
        }

        #[test]
        fn unknown_version_is_rejected() {
            let mut bad = RAG_MAGIC.to_vec();
            bad.push(99);
            assert!(matches!(
                decode_snapshot(&bad),
                Err(SnapshotError::BadVersion(99))
            ));
        }

        #[test]
        fn truncation_fails_closed() {
            // A valid prefix that ends mid-structure must fail cleanly, never panic.
            let store = populated();
            let path = std::env::temp_dir().join("cc_rag_trunc.ccrg");
            store.save(&path).unwrap();
            let full = std::fs::read(&path).unwrap();
            let _ = std::fs::remove_file(&path);
            // Truncate at every prefix length; none may panic, none may succeed at the full
            // structure unless it is the whole file.
            for cut in 0..full.len() {
                let res = decode_snapshot(&full[..cut]);
                assert!(
                    res.is_err(),
                    "a truncated snapshot (cut {cut}) must fail closed"
                );
            }
            // The whole file still decodes.
            assert!(decode_snapshot(&full).is_ok());
        }

        #[test]
        fn oversized_namespace_count_is_rejected_pre_alloc() {
            // header: magic | version | next_seq(8) | active_ns(len=0) | ns_count = huge
            let mut buf = RAG_MAGIC.to_vec();
            buf.push(RAG_VERSION);
            buf.extend_from_slice(&0u64.to_le_bytes());
            buf.extend_from_slice(&0u32.to_le_bytes()); // empty active namespace
            buf.extend_from_slice(&u32::MAX.to_le_bytes()); // ns_count
            assert!(matches!(
                decode_snapshot(&buf),
                Err(SnapshotError::BadContents)
            ));
        }

        #[test]
        fn oversized_entry_count_is_rejected_pre_alloc() {
            let mut buf = RAG_MAGIC.to_vec();
            buf.push(RAG_VERSION);
            buf.extend_from_slice(&0u64.to_le_bytes());
            buf.extend_from_slice(&0u32.to_le_bytes()); // empty active namespace
            buf.extend_from_slice(&1u32.to_le_bytes()); // ns_count = 1
            write_field(&mut buf, b"ns").unwrap(); // namespace name
            buf.extend_from_slice(&u32::MAX.to_le_bytes()); // entry_count = huge
            assert!(matches!(
                decode_snapshot(&buf),
                Err(SnapshotError::BadContents)
            ));
        }

        #[test]
        fn oversized_embedding_dim_is_rejected_pre_alloc() {
            let mut buf = RAG_MAGIC.to_vec();
            buf.push(RAG_VERSION);
            buf.extend_from_slice(&0u64.to_le_bytes());
            buf.extend_from_slice(&0u32.to_le_bytes()); // empty active namespace
            buf.extend_from_slice(&1u32.to_le_bytes()); // ns_count = 1
            write_field(&mut buf, b"ns").unwrap(); // namespace name
            buf.extend_from_slice(&1u32.to_le_bytes()); // entry_count = 1
            write_field(&mut buf, b"id").unwrap(); // chunk id
            buf.extend_from_slice(&0u64.to_le_bytes()); // seq
            buf.extend_from_slice(&u32::MAX.to_le_bytes()); // embedding dim = huge
            assert!(matches!(
                decode_snapshot(&buf),
                Err(SnapshotError::BadContents)
            ));
        }

        #[test]
        fn nonfinite_embeddings_round_trip_but_do_not_rank() {
            let mut store = LocalVectorStore::new();
            store.upsert(vec![(
                ChunkId::new("poison"),
                vec![f32::NAN, f32::INFINITY, f32::NEG_INFINITY],
                meta("p.rs"),
            )]);
            let path = std::env::temp_dir().join("cc_rag_nonfinite.ccrg");
            store.save(&path).unwrap();
            let loaded = LocalVectorStore::load(&path).unwrap();
            let _ = std::fs::remove_file(&path);
            // The bytes round-trip (bit-identical: NaN may differ in payload, so compare via
            // is_nan / is_infinite rather than ==).
            let stored = loaded
                .active()
                .unwrap()
                .get(&ChunkId::new("poison"))
                .unwrap();
            assert!(stored.embedding[0].is_nan());
            assert!(stored.embedding[1].is_infinite() && stored.embedding[1] > 0.0);
            assert!(stored.embedding[2].is_infinite() && stored.embedding[2] < 0.0);
            // cosine still sanitizes at query time, so it cannot rank.
            let hits = loaded.nearest(&[1.0, 1.0, 1.0], 5, 0.0);
            assert!(!hits.iter().any(|(id, _, _)| id.0 == "poison"));
        }
    }
}

#[cfg(feature = "persist")]
pub use persist::{
    SnapshotError, MAX_EMBED_DIM, MAX_ENTRIES_PER_NS, MAX_FIELD_BYTES, MAX_NAMESPACES, RAG_MAGIC,
    RAG_VERSION,
};

impl VectorStore for LocalVectorStore {
    fn upsert(&mut self, items: Vec<(ChunkId, Vec<f32>, ChunkMeta)>) {
        let ns = self.namespaces.entry(self.namespace.clone()).or_default();
        for (id, embedding, meta) in items {
            let seq = self.next_seq;
            self.next_seq += 1;
            // Idempotent on ChunkId: a duplicate/forged id REPLACES rather than
            // double-counts, so a backend caller cannot inflate the set with forged dupes.
            ns.insert(
                id,
                Stored {
                    embedding,
                    meta,
                    seq,
                },
            );
        }
    }

    fn nearest(&self, query: &[f32], k: usize, floor: f32) -> Vec<(ChunkId, f32, ChunkMeta)> {
        let Some(ns) = self.active() else {
            return Vec::new();
        };
        // Score every stored chunk; keep only positively-similar AND >= floor (same
        // positive-similarity gate as VectorMemory, plus the explicit floor). `cosine`
        // already sanitizes (finite-or-0, length-mismatch -> 0), so a NaN/inf embedding
        // cannot poison the ranking.
        let effective_floor = floor.max(0.0);
        let mut scored: Vec<(f32, u64, &ChunkId, &Stored)> = ns
            .iter()
            .map(|(id, s)| (cosine(query, &s.embedding), s.seq, id, s))
            .filter(|(score, _, _, _)| *score > 0.0 && *score >= effective_floor)
            .collect();
        // Descending score; ties resolve by ascending insertion seq (deterministic),
        // exactly like VectorMemory's `then(a.1.cmp(&b.1))` on the original index.
        scored.sort_by(|a, b| b.0.total_cmp(&a.0).then(a.1.cmp(&b.1)));
        scored
            .into_iter()
            .take(k)
            .map(|(score, _, id, s)| (id.clone(), score, s.meta.clone()))
            .collect()
    }

    fn delete(&mut self, id: &ChunkId) {
        if let Some(ns) = self.namespaces.get_mut(&self.namespace) {
            ns.remove(id);
        }
    }

    fn set_namespace(&mut self, namespace: &str) {
        self.namespace = namespace.to_string();
    }

    fn namespace(&self) -> &str {
        &self.namespace
    }

    fn len(&self) -> usize {
        self.active().map_or(0, BTreeMap::len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crustcore_index::embed::{Embedder, HashEmbedder, VectorMemory};
    use crustcore_index::{MemoryEntry, MemoryKind, MemorySource};
    use crustcore_types::BoundedText;

    use crate::store::ByteSpan;

    fn meta(path: &str) -> ChunkMeta {
        ChunkMeta::new(path, ByteSpan::new(0, 0), MemorySource::RepoFile)
    }

    #[test]
    fn local_backend_matches_vector_memory_semantics() {
        let e = HashEmbedder;
        // Same corpus into both a raw VectorMemory and the local backend.
        let docs = [
            ("verify", "cargo xtask verify fmt clippy test"),
            ("clippy", "clippy lints mistakes"),
            ("revenue", "quarterly revenue projections"),
        ];
        let mut vm = VectorMemory::new();
        let mut store = LocalVectorStore::new();
        for (key, text) in docs {
            vm.put(
                MemoryEntry {
                    kind: MemoryKind::CommandMemory,
                    key: BoundedText::truncated(key, 256),
                    value: BoundedText::truncated(text, 256),
                    source: MemorySource::ToolObservation,
                },
                e.embed(text),
            );
            store.upsert(vec![(ChunkId::new(key), e.embed(text), meta(key))]);
        }
        let q = e.embed("run cargo verify with clippy");
        let vm_hits: Vec<&str> = vm.nearest(&q, 5).iter().map(|m| m.key.as_str()).collect();
        let store_hits: Vec<String> = store
            .nearest(&q, 5, 0.0)
            .into_iter()
            .map(|(id, _, _)| id.0)
            .collect();
        // Same ranked set + order (positively-similar only, deterministic ties).
        assert_eq!(vm_hits, store_hits);
        // Top hit is the dominant match.
        assert_eq!(store_hits[0], "verify");
    }

    #[test]
    fn floor_and_positive_similarity_are_applied() {
        let e = HashEmbedder;
        let mut store = LocalVectorStore::new();
        let a_text = "alpha beta gamma";
        store.upsert(vec![(ChunkId::new("a"), e.embed(a_text), meta("a"))]);
        // A deterministically-orthogonal doc: a zero vector never scores positively
        // (cosine returns 0 for a zero vector), so it is always excluded regardless of
        // HashEmbedder bucket collisions.
        store.upsert(vec![(
            ChunkId::new("orthogonal"),
            vec![0.0; crustcore_index::embed::EMBED_DIM],
            meta("orthogonal"),
        )]);
        let q = e.embed("alpha beta");
        // The floor is an effective lower bound: every returned hit is >= the floor.
        let mid = store.nearest(&q, 5, 0.05);
        assert!(mid.iter().all(|(_, s, _)| *s >= 0.05));
        // Floor 0 keeps positively-similar only; the zero-vector doc is always excluded.
        let low = store.nearest(&q, 5, 0.0);
        assert!(low.iter().all(|(_, s, _)| *s > 0.0));
        assert!(low.iter().any(|(id, _, _)| id.0 == "a"));
        assert!(
            !low.iter().any(|(id, _, _)| id.0 == "orthogonal"),
            "a zero-vector (non-positive) hit must be excluded"
        );
        // A floor above any achievable score yields nothing (no panic).
        assert!(store.nearest(&q, 5, 1.001).is_empty());
    }

    #[test]
    fn upsert_is_idempotent_on_chunk_id() {
        let e = HashEmbedder;
        let mut store = LocalVectorStore::new();
        store.upsert(vec![(ChunkId::new("x"), e.embed("one"), meta("x"))]);
        store.upsert(vec![(ChunkId::new("x"), e.embed("two"), meta("x"))]);
        assert_eq!(store.len(), 1, "duplicate id replaces, not duplicates");
        store.delete(&ChunkId::new("x"));
        assert!(store.is_empty());
    }

    #[test]
    fn namespaces_partition_retrieval() {
        let e = HashEmbedder;
        let mut store = LocalVectorStore::new();
        store.set_namespace("ns1");
        store.upsert(vec![(ChunkId::new("a"), e.embed("hello world"), meta("a"))]);
        store.set_namespace("ns2");
        assert_eq!(store.len(), 0);
        let q = e.embed("hello");
        assert!(store.nearest(&q, 5, 0.0).is_empty());
        store.set_namespace("ns1");
        assert_eq!(store.len(), 1);
        assert!(!store.nearest(&q, 5, 0.0).is_empty());
    }

    #[test]
    fn nan_inf_embeddings_do_not_panic_or_rank() {
        let e = HashEmbedder;
        let mut store = LocalVectorStore::new();
        // A poisoned embedding (NaN/inf) cannot rank: cosine sanitizes finite-or-0.
        store.upsert(vec![(
            ChunkId::new("poison"),
            vec![f32::NAN, f32::INFINITY, f32::NEG_INFINITY],
            meta("poison"),
        )]);
        store.upsert(vec![(ChunkId::new("ok"), e.embed("alpha"), meta("ok"))]);
        let q = e.embed("alpha");
        let hits = store.nearest(&q, 5, 0.0);
        assert!(hits.iter().all(|(_, s, _)| s.is_finite() && *s > 0.0));
        assert!(!hits.iter().any(|(id, _, _)| id.0 == "poison"));
    }
}

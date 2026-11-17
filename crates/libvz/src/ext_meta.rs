use crate::error::VzError;
use crate::wire::{
    ByteOrder, read_le_u16, read_le_u32, read_le_u64, read_levint_safe, write_le_u16,
    write_le_u32, write_le_u64, write_levint, SCHEMA_KIND_COLUMN, SCHEMA_KIND_TENSOR,
};

// ============================================================================
// PATH NORMALIZATION HELPERS
// ============================================================================

/// Normalizes a directory path into canonical archive form (`"/"` or `"/a/b"`).
pub fn normalize_dir_path(path: &str) -> Result<String, VzError> {
    let mut parts = Vec::new();
    for seg in path.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            return Err(VzError::InvalidInput);
        }
        parts.push(seg);
    }
    if parts.is_empty() {
        Ok("/".to_string())
    } else {
        Ok(format!("/{}", parts.join("/")))
    }
}

/// Zero-allocation canonical fast path returning `(parent_path, basename)` as borrowed slices
/// whenever `path` already has no redundant slashes, `.`, or `..` segments; falls back cleanly
/// to normalized owned strings otherwise.
pub fn split_archive_path_borrowed<'a>(
    path: &'a str,
) -> Result<(std::borrow::Cow<'a, str>, std::borrow::Cow<'a, str>), VzError> {
    use std::borrow::Cow;
    if !path.is_empty() && !path.contains("//") && !path.ends_with('/') {
        let bytes = path.as_bytes();
        // Check for "." or ".." segments directly without allocating.
        let mut valid_fast = true;
        let trimmed = path.strip_prefix('/').unwrap_or(path);
        if trimmed.is_empty() {
            return Err(VzError::InvalidInput);
        }
        for seg in trimmed.split('/') {
            if seg.is_empty() || seg == "." || seg == ".." {
                valid_fast = false;
                break;
            }
        }
        if valid_fast {
            if bytes[0] == b'/' {
                if let Some(pos) = path.rfind('/') {
                    let parent = if pos == 0 { "/" } else { &path[..pos] };
                    return Ok((Cow::Borrowed(parent), Cow::Borrowed(&path[pos + 1..])));
                }
            } else if let Some(pos) = path.rfind('/') {
                return Ok((
                    Cow::Owned(format!("/{}", &path[..pos])),
                    Cow::Borrowed(&path[pos + 1..]),
                ));
            } else {
                return Ok((Cow::Borrowed("/"), Cow::Borrowed(path)));
            }
        }
    }
    let (p, b) = split_archive_path(path)?;
    Ok((Cow::Owned(p), Cow::Owned(b)))
}

/// Normalizes an entry path and splits it into `(normalized_parent_path, basename)`.
///
/// For `"hello.txt"` or `"/hello.txt"`, returns `("/", "hello.txt")`.
/// For `"a/b/c.txt"`, returns `("/a/b", "c.txt")`.
pub fn split_archive_path(path: &str) -> Result<(String, String), VzError> {
    let mut parts = Vec::new();
    for seg in path.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            return Err(VzError::InvalidInput);
        }
        parts.push(seg);
    }
    let Some(basename) = parts.pop() else {
        return Err(VzError::InvalidInput);
    };
    let parent = if parts.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", parts.join("/"))
    };
    Ok((parent, basename.to_string()))
}

// ============================================================================
// LE-VINT / TLV WRITE HELPERS
// ============================================================================

/// Appends an LE-VINT-encoded `val` to `out`.
pub fn push_levint(out: &mut Vec<u8>, val: u64) -> Result<(), VzError> {
    let mut buf = [0u8; 8];
    let w = write_levint(&mut buf, val)?;
    out.extend_from_slice(&buf[..w]);
    Ok(())
}

/// Appends a complete `[Tag: LE-VINT][Len: LE-VINT][Value]` TLV element to `out`.
pub fn push_tlv(out: &mut Vec<u8>, tag: u64, value: &[u8]) -> Result<(), VzError> {
    push_levint(out, tag)?;
    push_levint(out, value.len() as u64)?;
    out.extend_from_slice(value);
    Ok(())
}

/// Appends a length-prefixed byte slice `[LE-VINT len][bytes]` to `out`.
pub fn push_lp_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), VzError> {
    push_levint(out, bytes.len() as u64)?;
    out.extend_from_slice(bytes);
    Ok(())
}

/// Reads a length-prefixed byte slice `[LE-VINT len][bytes]` from `buf`, returning `(slice, rest)`.
pub fn read_lp_bytes(buf: &[u8]) -> Result<(&[u8], &[u8]), VzError> {
    let (len, w) = read_levint_safe(buf)?;
    let len_usize = usize::try_from(len).map_err(|_| VzError::ValueOverflow)?;
    let end = w.checked_add(len_usize).ok_or(VzError::ValueOverflow)?;
    if end > buf.len() {
        return Err(VzError::BufferTooSmall);
    }
    Ok((&buf[w..end], &buf[end..]))
}

// ============================================================================
// OWNER TABLE & EXTENDED OWNER
// ============================================================================

/// POSIX owner record stored in `TAG_OWNER_TABLE` or `TAG_EXT_OWNER`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerEntry {
    pub uid: u32,
    pub gid: u32,
    pub uname: String,
    pub gname: String,
}

/// Encodes `owners` into the value payload of `TAG_OWNER_TABLE`.
pub fn encode_owner_table(owners: &[OwnerEntry]) -> Result<Vec<u8>, VzError> {
    if owners.len() > 255 {
        return Err(VzError::ValueOverflow);
    }
    let mut out = Vec::with_capacity(2 + owners.len() * 16);
    out.extend_from_slice(&(owners.len() as u16).to_le_bytes());
    for o in owners {
        out.extend_from_slice(&o.uid.to_le_bytes());
        out.extend_from_slice(&o.gid.to_le_bytes());
        push_lp_bytes(&mut out, o.uname.as_bytes())?;
        push_lp_bytes(&mut out, o.gname.as_bytes())?;
    }
    Ok(out)
}

/// Decodes the value payload of `TAG_OWNER_TABLE`.
pub fn decode_owner_table(buf: &[u8]) -> Result<Vec<OwnerEntry>, VzError> {
    if buf.len() < 2 {
        return Err(VzError::BufferTooSmall);
    }
    let count = read_le_u16(buf, 0) as usize;
    let mut rem = &buf[2..];
    let mut out = Vec::with_capacity(count.min(256));
    for _ in 0..count {
        if rem.len() < 8 {
            return Err(VzError::BufferTooSmall);
        }
        let uid = read_le_u32(rem, 0);
        let gid = read_le_u32(rem, 4);
        let (uname_b, r1) = read_lp_bytes(&rem[8..])?;
        let (gname_b, r2) = read_lp_bytes(r1)?;
        let uname = core::str::from_utf8(uname_b)
            .map_err(|_| VzError::BadFormat)?
            .to_string();
        let gname = core::str::from_utf8(gname_b)
            .map_err(|_| VzError::BadFormat)?
            .to_string();
        out.push(OwnerEntry {
            uid,
            gid,
            uname,
            gname,
        });
        rem = r2;
    }
    Ok(out)
}

/// Encodes an extended owner record for `TAG_EXT_OWNER`.
pub fn encode_ext_owner(owner: &OwnerEntry) -> Result<Vec<u8>, VzError> {
    let mut out = Vec::with_capacity(16);
    out.extend_from_slice(&owner.uid.to_le_bytes());
    out.extend_from_slice(&owner.gid.to_le_bytes());
    push_lp_bytes(&mut out, owner.uname.as_bytes())?;
    push_lp_bytes(&mut out, owner.gname.as_bytes())?;
    Ok(out)
}

/// Decodes `TAG_EXT_OWNER`.
pub fn decode_ext_owner(buf: &[u8]) -> Result<OwnerEntry, VzError> {
    if buf.len() < 8 {
        return Err(VzError::BufferTooSmall);
    }
    let uid = read_le_u32(buf, 0);
    let gid = read_le_u32(buf, 4);
    let (uname_b, r1) = read_lp_bytes(&buf[8..])?;
    let (gname_b, _) = read_lp_bytes(r1)?;
    Ok(OwnerEntry {
        uid,
        gid,
        uname: core::str::from_utf8(uname_b)
            .map_err(|_| VzError::BadFormat)?
            .to_string(),
        gname: core::str::from_utf8(gname_b)
            .map_err(|_| VzError::BadFormat)?
            .to_string(),
    })
}

// ============================================================================
// DICTIONARY TABLE (`TAG_DICT_TABLE`)
// ============================================================================

/// Shared compression dictionary stored in `TAG_DICT_TABLE`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DictEntry {
    pub dict_id: u32,
    pub codec: u8,
    pub flags: u8,
    pub bytes: Vec<u8>,
}

/// Encodes `dicts` into the value payload of `TAG_DICT_TABLE`.
pub fn encode_dict_table(dicts: &[DictEntry]) -> Result<Vec<u8>, VzError> {
    let count = u16::try_from(dicts.len()).map_err(|_| VzError::ValueOverflow)?;
    let mut out = Vec::new();
    out.extend_from_slice(&count.to_le_bytes());
    for d in dicts {
        out.extend_from_slice(&d.dict_id.to_le_bytes());
        out.push(d.codec);
        out.push(d.flags);
        push_lp_bytes(&mut out, &d.bytes)?;
    }
    Ok(out)
}

/// Decodes `TAG_DICT_TABLE`.
pub fn decode_dict_table(buf: &[u8]) -> Result<Vec<DictEntry>, VzError> {
    if buf.len() < 2 {
        return Err(VzError::BufferTooSmall);
    }
    let count = read_le_u16(buf, 0) as usize;
    let mut rem = &buf[2..];
    let mut out = Vec::with_capacity(count.min(64));
    for _ in 0..count {
        if rem.len() < 6 {
            return Err(VzError::BufferTooSmall);
        }
        let dict_id = read_le_u32(rem, 0);
        let codec = rem[4];
        let flags = rem[5];
        let (bytes, r) = read_lp_bytes(&rem[6..])?;
        out.push(DictEntry {
            dict_id,
            codec,
            flags,
            bytes: bytes.to_vec(),
        });
        rem = r;
    }
    Ok(out)
}

// ============================================================================
// SCHEMA TABLE (`TAG_SCHEMA_TABLE`) — TENSORS & COLUMNS
// ============================================================================

/// Tensor element data type (`SCHEMA_KIND_TENSOR`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TensorDtype {
    U8 = 0,
    I8 = 1,
    U16 = 2,
    I16 = 3,
    U32 = 4,
    I32 = 5,
    U64 = 6,
    I64 = 7,
    F16 = 8,
    Bf16 = 9,
    F32 = 10,
    F64 = 11,
    Bool = 12,
}

impl TryFrom<u8> for TensorDtype {
    type Error = VzError;
    fn try_from(v: u8) -> Result<Self, VzError> {
        match v {
            0 => Ok(Self::U8),
            1 => Ok(Self::I8),
            2 => Ok(Self::U16),
            3 => Ok(Self::I16),
            4 => Ok(Self::U32),
            5 => Ok(Self::I32),
            6 => Ok(Self::U64),
            7 => Ok(Self::I64),
            8 => Ok(Self::F16),
            9 => Ok(Self::Bf16),
            10 => Ok(Self::F32),
            11 => Ok(Self::F64),
            12 => Ok(Self::Bool),
            _ => Err(VzError::BadFormat),
        }
    }
}

/// Column logical type (`SCHEMA_KIND_COLUMN`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ColumnLogicalType {
    Null = 0,
    Bool = 1,
    Int64 = 2,
    UInt64 = 3,
    Float64 = 4,
    Binary = 5,
    Utf8 = 6,
    Decimal128 = 7,
    TimestampNs = 8,
}

impl TryFrom<u8> for ColumnLogicalType {
    type Error = VzError;
    fn try_from(v: u8) -> Result<Self, VzError> {
        match v {
            0 => Ok(Self::Null),
            1 => Ok(Self::Bool),
            2 => Ok(Self::Int64),
            3 => Ok(Self::UInt64),
            4 => Ok(Self::Float64),
            5 => Ok(Self::Binary),
            6 => Ok(Self::Utf8),
            7 => Ok(Self::Decimal128),
            8 => Ok(Self::TimestampNs),
            _ => Err(VzError::BadFormat),
        }
    }
}

/// Column encoding scheme (`SCHEMA_KIND_COLUMN`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ColumnEncoding {
    Plain = 0,
    Dictionary = 1,
    Rle = 2,
    DeltaBinaryPacked = 3,
}

impl TryFrom<u8> for ColumnEncoding {
    type Error = VzError;
    fn try_from(v: u8) -> Result<Self, VzError> {
        match v {
            0 => Ok(Self::Plain),
            1 => Ok(Self::Dictionary),
            2 => Ok(Self::Rle),
            3 => Ok(Self::DeltaBinaryPacked),
            _ => Err(VzError::BadFormat),
        }
    }
}

impl TensorDtype {
    /// Returns the element storage width in bytes for this [`TensorDtype`].
    #[inline]
    pub const fn byte_size(self) -> usize {
        match self {
            Self::U8 | Self::I8 | Self::Bool => 1,
            Self::U16 | Self::I16 | Self::F16 | Self::Bf16 => 2,
            Self::U32 | Self::I32 | Self::F32 => 4,
            Self::U64 | Self::I64 | Self::F64 => 8,
        }
    }
}

/// Tensor metadata record in `TAG_SCHEMA_TABLE`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TensorMeta {
    pub schema_id: u32,
    pub name: String,
    pub dtype: TensorDtype,
    pub byte_order: u8,
    pub dims: Vec<u64>,
    pub strides: Vec<u64>,
}

impl TensorMeta {
    /// Parses `self.byte_order` as a [`ByteOrder`] (`0 = LittleEndian`, `1 = BigEndian`).
    #[inline]
    pub fn order(&self) -> Result<ByteOrder, VzError> {
        ByteOrder::try_from(self.byte_order)
    }

    /// Computes total logical element count across `self.dims` (returns `1` for rank-0 scalars).
    pub fn element_count(&self) -> Result<usize, VzError> {
        let mut prod = 1u64;
        for &d in &self.dims {
            prod = prod.checked_mul(d).ok_or(VzError::ValueOverflow)?;
        }
        usize::try_from(prod).map_err(|_| VzError::ValueOverflow)
    }

    /// Returns the exact contiguous payload size in bytes (`element_count * dtype.byte_size()`).
    pub fn payload_byte_len(&self) -> Result<usize, VzError> {
        let elems = self.element_count()?;
        elems
            .checked_mul(self.dtype.byte_size())
            .ok_or(VzError::ValueOverflow)
    }

    fn decode_typed<T, F>(
        &self,
        expected: TensorDtype,
        raw: &[u8],
        read_fn: F,
    ) -> Result<Vec<T>, VzError>
    where
        F: Fn(ByteOrder, &[u8], usize) -> T,
    {
        if self.dtype != expected {
            return Err(VzError::InvalidInput);
        }
        let order = self.order()?;
        let count = self.element_count()?;
        let width = expected.byte_size();
        let needed = count.checked_mul(width).ok_or(VzError::ValueOverflow)?;
        if raw.len() != needed {
            return Err(VzError::BadFormat);
        }
        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            out.push(read_fn(order, raw, i * width));
        }
        Ok(out)
    }

    fn encode_typed<T: Copy, F>(
        &self,
        expected: TensorDtype,
        vals: &[T],
        write_fn: F,
    ) -> Result<Vec<u8>, VzError>
    where
        F: Fn(ByteOrder, &mut [u8], usize, T),
    {
        if self.dtype != expected {
            return Err(VzError::InvalidInput);
        }
        let order = self.order()?;
        let count = self.element_count()?;
        if vals.len() != count {
            return Err(VzError::InvalidInput);
        }
        let width = expected.byte_size();
        let needed = count.checked_mul(width).ok_or(VzError::ValueOverflow)?;
        let mut out = vec![0u8; needed];
        for (i, &v) in vals.iter().enumerate() {
            write_fn(order, &mut out, i * width, v);
        }
        Ok(out)
    }

    /// Decodes a `U16` tensor payload respecting `self.byte_order` without alignment assumptions.
    pub fn decode_u16(&self, raw: &[u8]) -> Result<Vec<u16>, VzError> {
        self.decode_typed(TensorDtype::U16, raw, ByteOrder::read_u16)
    }

    /// Encodes `vals` into a `U16` tensor payload using `self.byte_order`.
    pub fn encode_u16(&self, vals: &[u16]) -> Result<Vec<u8>, VzError> {
        self.encode_typed(TensorDtype::U16, vals, ByteOrder::write_u16)
    }

    /// Decodes an `I16` tensor payload respecting `self.byte_order` without alignment assumptions.
    pub fn decode_i16(&self, raw: &[u8]) -> Result<Vec<i16>, VzError> {
        self.decode_typed(TensorDtype::I16, raw, ByteOrder::read_i16)
    }

    /// Encodes `vals` into an `I16` tensor payload using `self.byte_order`.
    pub fn encode_i16(&self, vals: &[i16]) -> Result<Vec<u8>, VzError> {
        self.encode_typed(TensorDtype::I16, vals, ByteOrder::write_i16)
    }

    /// Decodes a `U32` tensor payload respecting `self.byte_order` without alignment assumptions.
    pub fn decode_u32(&self, raw: &[u8]) -> Result<Vec<u32>, VzError> {
        self.decode_typed(TensorDtype::U32, raw, ByteOrder::read_u32)
    }

    /// Encodes `vals` into a `U32` tensor payload using `self.byte_order`.
    pub fn encode_u32(&self, vals: &[u32]) -> Result<Vec<u8>, VzError> {
        self.encode_typed(TensorDtype::U32, vals, ByteOrder::write_u32)
    }

    /// Decodes an `I32` tensor payload respecting `self.byte_order` without alignment assumptions.
    pub fn decode_i32(&self, raw: &[u8]) -> Result<Vec<i32>, VzError> {
        self.decode_typed(TensorDtype::I32, raw, ByteOrder::read_i32)
    }

    /// Encodes `vals` into an `I32` tensor payload using `self.byte_order`.
    pub fn encode_i32(&self, vals: &[i32]) -> Result<Vec<u8>, VzError> {
        self.encode_typed(TensorDtype::I32, vals, ByteOrder::write_i32)
    }

    /// Decodes a `U64` tensor payload respecting `self.byte_order` without alignment assumptions.
    pub fn decode_u64(&self, raw: &[u8]) -> Result<Vec<u64>, VzError> {
        self.decode_typed(TensorDtype::U64, raw, ByteOrder::read_u64)
    }

    /// Encodes `vals` into a `U64` tensor payload using `self.byte_order`.
    pub fn encode_u64(&self, vals: &[u64]) -> Result<Vec<u8>, VzError> {
        self.encode_typed(TensorDtype::U64, vals, ByteOrder::write_u64)
    }

    /// Decodes an `I64` tensor payload respecting `self.byte_order` without alignment assumptions.
    pub fn decode_i64(&self, raw: &[u8]) -> Result<Vec<i64>, VzError> {
        self.decode_typed(TensorDtype::I64, raw, ByteOrder::read_i64)
    }

    /// Encodes `vals` into an `I64` tensor payload using `self.byte_order`.
    pub fn encode_i64(&self, vals: &[i64]) -> Result<Vec<u8>, VzError> {
        self.encode_typed(TensorDtype::I64, vals, ByteOrder::write_i64)
    }

    /// Decodes an `F32` tensor payload respecting `self.byte_order` without alignment assumptions.
    pub fn decode_f32(&self, raw: &[u8]) -> Result<Vec<f32>, VzError> {
        self.decode_typed(TensorDtype::F32, raw, ByteOrder::read_f32)
    }

    /// Encodes `vals` into an `F32` tensor payload using `self.byte_order`.
    pub fn encode_f32(&self, vals: &[f32]) -> Result<Vec<u8>, VzError> {
        self.encode_typed(TensorDtype::F32, vals, ByteOrder::write_f32)
    }

    /// Decodes an `F64` tensor payload respecting `self.byte_order` without alignment assumptions.
    pub fn decode_f64(&self, raw: &[u8]) -> Result<Vec<f64>, VzError> {
        self.decode_typed(TensorDtype::F64, raw, ByteOrder::read_f64)
    }

    /// Encodes `vals` into an `F64` tensor payload using `self.byte_order`.
    pub fn encode_f64(&self, vals: &[f64]) -> Result<Vec<u8>, VzError> {
        self.encode_typed(TensorDtype::F64, vals, ByteOrder::write_f64)
    }
}

/// Analytical column metadata record in `TAG_SCHEMA_TABLE`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColumnMeta {
    pub schema_id: u32,
    pub name: String,
    pub logical_type: ColumnLogicalType,
    pub encoding: ColumnEncoding,
    pub row_count: u64,
    pub null_count: u64,
    pub min_stat: Option<Vec<u8>>,
    pub max_stat: Option<Vec<u8>>,
}

/// Schema table entry in `TAG_SCHEMA_TABLE`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaEntry {
    Tensor(TensorMeta),
    Column(ColumnMeta),
}

impl SchemaEntry {
    pub fn schema_id(&self) -> u32 {
        match self {
            Self::Tensor(t) => t.schema_id,
            Self::Column(c) => c.schema_id,
        }
    }
}

/// Encodes `schemas` into the value payload of `TAG_SCHEMA_TABLE`.
pub fn encode_schema_table(schemas: &[SchemaEntry]) -> Result<Vec<u8>, VzError> {
    let count = u32::try_from(schemas.len()).map_err(|_| VzError::ValueOverflow)?;
    let mut out = Vec::new();
    out.extend_from_slice(&count.to_le_bytes());
    for s in schemas {
        match s {
            SchemaEntry::Tensor(t) => {
                if t.dims.len() != t.strides.len() {
                    return Err(VzError::InvalidInput);
                }
                let ndim = u16::try_from(t.dims.len()).map_err(|_| VzError::ValueOverflow)?;
                out.extend_from_slice(&t.schema_id.to_le_bytes());
                out.push(SCHEMA_KIND_TENSOR);
                push_lp_bytes(&mut out, t.name.as_bytes())?;
                out.push(t.dtype as u8);
                out.push(t.byte_order);
                out.extend_from_slice(&ndim.to_le_bytes());
                for &d in &t.dims {
                    out.extend_from_slice(&d.to_le_bytes());
                }
                for &st in &t.strides {
                    out.extend_from_slice(&st.to_le_bytes());
                }
            }
            SchemaEntry::Column(c) => {
                out.extend_from_slice(&c.schema_id.to_le_bytes());
                out.push(SCHEMA_KIND_COLUMN);
                push_lp_bytes(&mut out, c.name.as_bytes())?;
                out.push(c.logical_type as u8);
                out.push(c.encoding as u8);
                let has_stats = u8::from(c.min_stat.is_some() || c.max_stat.is_some());
                out.push(has_stats);
                out.extend_from_slice(&c.row_count.to_le_bytes());
                out.extend_from_slice(&c.null_count.to_le_bytes());
                if has_stats != 0 {
                    push_lp_bytes(&mut out, c.min_stat.as_deref().unwrap_or(&[]))?;
                    push_lp_bytes(&mut out, c.max_stat.as_deref().unwrap_or(&[]))?;
                }
            }
        }
    }
    Ok(out)
}

/// Decodes `TAG_SCHEMA_TABLE`.
pub fn decode_schema_table(buf: &[u8]) -> Result<Vec<SchemaEntry>, VzError> {
    if buf.len() < 4 {
        return Err(VzError::BufferTooSmall);
    }
    let count = read_le_u32(buf, 0) as usize;
    let mut rem = &buf[4..];
    let mut out = Vec::with_capacity(count.min(1024));
    for _ in 0..count {
        if rem.len() < 5 {
            return Err(VzError::BufferTooSmall);
        }
        let schema_id = read_le_u32(rem, 0);
        let kind = rem[4];
        let (name_b, r1) = read_lp_bytes(&rem[5..])?;
        let name = core::str::from_utf8(name_b)
            .map_err(|_| VzError::BadFormat)?
            .to_string();
        match kind {
            SCHEMA_KIND_TENSOR => {
                if r1.len() < 4 {
                    return Err(VzError::BufferTooSmall);
                }
                let dtype = TensorDtype::try_from(r1[0])?;
                let byte_order = r1[1];
                let ndim = read_le_u16(r1, 2) as usize;
                let vec_bytes = ndim.checked_mul(16).ok_or(VzError::ValueOverflow)?;
                if r1.len() < 4 + vec_bytes {
                    return Err(VzError::BufferTooSmall);
                }
                let mut dims = Vec::with_capacity(ndim);
                let mut strides = Vec::with_capacity(ndim);
                for i in 0..ndim {
                    dims.push(read_le_u64(r1, 4 + i * 8));
                }
                for i in 0..ndim {
                    strides.push(read_le_u64(r1, 4 + ndim * 8 + i * 8));
                }
                out.push(SchemaEntry::Tensor(TensorMeta {
                    schema_id,
                    name,
                    dtype,
                    byte_order,
                    dims,
                    strides,
                }));
                rem = &r1[4 + vec_bytes..];
            }
            SCHEMA_KIND_COLUMN => {
                if r1.len() < 19 {
                    return Err(VzError::BufferTooSmall);
                }
                let logical_type = ColumnLogicalType::try_from(r1[0])?;
                let encoding = ColumnEncoding::try_from(r1[1])?;
                let has_stats = r1[2];
                let row_count = read_le_u64(r1, 3);
                let null_count = read_le_u64(r1, 11);
                let mut r_cur = &r1[19..];
                let (min_stat, max_stat) = if has_stats != 0 {
                    let (min_b, r2) = read_lp_bytes(r_cur)?;
                    let (max_b, r3) = read_lp_bytes(r2)?;
                    r_cur = r3;
                    (Some(min_b.to_vec()), Some(max_b.to_vec()))
                } else {
                    (None, None)
                };
                out.push(SchemaEntry::Column(ColumnMeta {
                    schema_id,
                    name,
                    logical_type,
                    encoding,
                    row_count,
                    null_count,
                    min_stat,
                    max_stat,
                }));
                rem = r_cur;
            }
            _ => return Err(VzError::BadFormat),
        }
    }
    Ok(out)
}

// ============================================================================
// CIPHER HEADER (`TAG_CIPHER_HEADER`)
// ============================================================================

/// Fixed 104-byte `TAG_CIPHER_HEADER` payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CipherHeader {
    pub version: u8,
    pub kdf_mode: u8,
    pub cipher_suite: u8,
    pub reserved: u8,
    pub argon2_m_cost_kib: u32,
    pub argon2_t_cost: u32,
    pub argon2_p_cost: u32,
    pub salt: [u8; 16],
    pub wrap_nonce: [u8; 24],
    pub wrapped_cek: [u8; 48],
}

impl CipherHeader {
    pub const SIZE: usize = 104;

    pub fn from_bytes(buf: &[u8]) -> Result<Self, VzError> {
        if buf.len() < Self::SIZE {
            return Err(VzError::BufferTooSmall);
        }
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&buf[16..32]);
        let mut wrap_nonce = [0u8; 24];
        wrap_nonce.copy_from_slice(&buf[32..56]);
        let mut wrapped_cek = [0u8; 48];
        wrapped_cek.copy_from_slice(&buf[56..104]);
        Ok(Self {
            version: buf[0],
            kdf_mode: buf[1],
            cipher_suite: buf[2],
            reserved: buf[3],
            argon2_m_cost_kib: read_le_u32(buf, 4),
            argon2_t_cost: read_le_u32(buf, 8),
            argon2_p_cost: read_le_u32(buf, 12),
            salt,
            wrap_nonce,
            wrapped_cek,
        })
    }

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut out = [0u8; Self::SIZE];
        out[0] = self.version;
        out[1] = self.kdf_mode;
        out[2] = self.cipher_suite;
        out[3] = self.reserved;
        write_le_u32(&mut out, 4, self.argon2_m_cost_kib);
        write_le_u32(&mut out, 8, self.argon2_t_cost);
        write_le_u32(&mut out, 12, self.argon2_p_cost);
        out[16..32].copy_from_slice(&self.salt);
        out[32..56].copy_from_slice(&self.wrap_nonce);
        out[56..104].copy_from_slice(&self.wrapped_cek);
        out
    }
}

// ============================================================================
// LSM RUN DESCRIPTORS (`TAG_LSM_RUNS`)
// ============================================================================

/// Descriptor for a single B+Tree run in `TAG_LSM_RUNS` (`24` bytes on wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LsmRunDesc {
    pub run_generation: u64,
    pub root_offset: u64,
    pub root_entry_count: u32,
    pub tree_height: u8,
    pub root_is_cluster: bool,
}

impl LsmRunDesc {
    pub const SIZE: usize = 24;
}

/// Encodes `runs` into `TAG_LSM_RUNS`.
pub fn encode_lsm_runs(runs: &[LsmRunDesc]) -> Result<Vec<u8>, VzError> {
    let count = u16::try_from(runs.len()).map_err(|_| VzError::ValueOverflow)?;
    let mut out = Vec::with_capacity(4 + runs.len() * LsmRunDesc::SIZE);
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    for r in runs {
        out.extend_from_slice(&r.run_generation.to_le_bytes());
        out.extend_from_slice(&r.root_offset.to_le_bytes());
        out.extend_from_slice(&r.root_entry_count.to_le_bytes());
        out.push(r.tree_height);
        out.push(u8::from(r.root_is_cluster));
        out.extend_from_slice(&0u16.to_le_bytes());
    }
    Ok(out)
}

/// Decodes `TAG_LSM_RUNS`.
pub fn decode_lsm_runs(buf: &[u8]) -> Result<Vec<LsmRunDesc>, VzError> {
    if buf.len() < 4 {
        return Err(VzError::BufferTooSmall);
    }
    let count = read_le_u16(buf, 0) as usize;
    let needed = 4usize
        .checked_add(
            count
                .checked_mul(LsmRunDesc::SIZE)
                .ok_or(VzError::ValueOverflow)?,
        )
        .ok_or(VzError::ValueOverflow)?;
    if buf.len() < needed {
        return Err(VzError::BufferTooSmall);
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let off = 4 + i * LsmRunDesc::SIZE;
        out.push(LsmRunDesc {
            run_generation: read_le_u64(buf, off),
            root_offset: read_le_u64(buf, off + 8),
            root_entry_count: read_le_u32(buf, off + 16),
            tree_height: buf[off + 20],
            root_is_cluster: buf[off + 21] != 0,
        });
    }
    Ok(out)
}

// ============================================================================
// EXTENDED METADATA POOL RECORDS
// ============================================================================

/// POSIX extended attribute (`TAG_XATTR_LIST`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Xattr {
    pub key: String,
    pub value: Vec<u8>,
}

/// Encodes `xattrs` for `TAG_XATTR_LIST`.
pub fn encode_xattr_list(xattrs: &[Xattr]) -> Result<Vec<u8>, VzError> {
    let mut out = Vec::new();
    push_levint(&mut out, xattrs.len() as u64)?;
    for x in xattrs {
        push_lp_bytes(&mut out, x.key.as_bytes())?;
        push_lp_bytes(&mut out, &x.value)?;
    }
    Ok(out)
}

/// Decodes `TAG_XATTR_LIST`.
pub fn decode_xattr_list(buf: &[u8]) -> Result<Vec<Xattr>, VzError> {
    let (count_u64, w) = read_levint_safe(buf)?;
    let count = usize::try_from(count_u64).map_err(|_| VzError::ValueOverflow)?;
    let mut rem = &buf[w..];
    let mut out = Vec::with_capacity(count.min(256));
    for _ in 0..count {
        let (k, r1) = read_lp_bytes(rem)?;
        let (v, r2) = read_lp_bytes(r1)?;
        out.push(Xattr {
            key: core::str::from_utf8(k)
                .map_err(|_| VzError::BadFormat)?
                .to_string(),
            value: v.to_vec(),
        });
        rem = r2;
    }
    Ok(out)
}

/// Non-zero logical extent for a sparse file (`TAG_SPARSE_EXTENTS`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SparseExtent {
    pub logical_offset: u64,
    pub length: u64,
}

/// Encodes `extents` for `TAG_SPARSE_EXTENTS`.
pub fn encode_sparse_extents(extents: &[SparseExtent]) -> Result<Vec<u8>, VzError> {
    let mut out = Vec::with_capacity(8 + extents.len() * 16);
    push_levint(&mut out, extents.len() as u64)?;
    for ext in extents {
        out.extend_from_slice(&ext.logical_offset.to_le_bytes());
        out.extend_from_slice(&ext.length.to_le_bytes());
    }
    Ok(out)
}

/// Decodes `TAG_SPARSE_EXTENTS`.
pub fn decode_sparse_extents(buf: &[u8]) -> Result<Vec<SparseExtent>, VzError> {
    let (count_u64, w) = read_levint_safe(buf)?;
    let count = usize::try_from(count_u64).map_err(|_| VzError::ValueOverflow)?;
    let needed = w
        .checked_add(count.checked_mul(16).ok_or(VzError::ValueOverflow)?)
        .ok_or(VzError::ValueOverflow)?;
    if buf.len() < needed {
        return Err(VzError::BufferTooSmall);
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let off = w + i * 16;
        out.push(SparseExtent {
            logical_offset: read_le_u64(buf, off),
            length: read_le_u64(buf, off + 8),
        });
    }
    Ok(out)
}

/// Extended codec link (`TAG_EXT_CODEC`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtCodecMeta {
    pub ext_codec_id: u16,
    pub dict_id: u32,
    pub params: Vec<u8>,
}

/// Encodes `TAG_EXT_CODEC`.
pub fn encode_ext_codec(meta: &ExtCodecMeta) -> Result<Vec<u8>, VzError> {
    let mut out = Vec::with_capacity(8 + meta.params.len());
    out.extend_from_slice(&meta.ext_codec_id.to_le_bytes());
    out.extend_from_slice(&meta.dict_id.to_le_bytes());
    push_lp_bytes(&mut out, &meta.params)?;
    Ok(out)
}

/// Decodes `TAG_EXT_CODEC`.
pub fn decode_ext_codec(buf: &[u8]) -> Result<ExtCodecMeta, VzError> {
    if buf.len() < 6 {
        return Err(VzError::BufferTooSmall);
    }
    let ext_codec_id = read_le_u16(buf, 0);
    let dict_id = read_le_u32(buf, 2);
    let (params, _) = read_lp_bytes(&buf[6..])?;
    Ok(ExtCodecMeta {
        ext_codec_id,
        dict_id,
        params: params.to_vec(),
    })
}

/// Schema link (`TAG_SCHEMA_LINK`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaLinkMeta {
    pub schema_id: u32,
    pub extra: Vec<u8>,
}

/// Encodes `TAG_SCHEMA_LINK`.
pub fn encode_schema_link(link: &SchemaLinkMeta) -> Result<Vec<u8>, VzError> {
    let extra_len = u16::try_from(link.extra.len()).map_err(|_| VzError::ValueOverflow)?;
    let mut out = Vec::with_capacity(6 + link.extra.len());
    out.extend_from_slice(&link.schema_id.to_le_bytes());
    out.extend_from_slice(&extra_len.to_le_bytes());
    out.extend_from_slice(&link.extra);
    Ok(out)
}

/// Decodes `TAG_SCHEMA_LINK`.
pub fn decode_schema_link(buf: &[u8]) -> Result<SchemaLinkMeta, VzError> {
    if buf.len() < 6 {
        return Err(VzError::BufferTooSmall);
    }
    let schema_id = read_le_u32(buf, 0);
    let extra_len = read_le_u16(buf, 4) as usize;
    if buf.len() < 6 + extra_len {
        return Err(VzError::BufferTooSmall);
    }
    Ok(SchemaLinkMeta {
        schema_id,
        extra: buf[6..6 + extra_len].to_vec(),
    })
}

// ============================================================================
// CLUSTER PAYLOADS: CHUNK TABLE, DATA MANIFEST, ROOT FALLBACK
// ============================================================================

/// Multi-cluster extent record (`28` bytes on wire, inside `TAG_CHUNK_TABLE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkExtent {
    pub cluster_offset: u64,
    pub in_cluster_offset: u32,
    pub stored_size: u64,
    pub raw_size: u64,
}

impl ChunkExtent {
    pub const SIZE: usize = 28;
}

/// Encodes `TAG_CHUNK_TABLE` value bytes.
pub fn encode_chunk_table(extents: &[ChunkExtent]) -> Result<Vec<u8>, VzError> {
    let count = u32::try_from(extents.len()).map_err(|_| VzError::ValueOverflow)?;
    let mut out = Vec::with_capacity(8 + extents.len() * ChunkExtent::SIZE);
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    for e in extents {
        out.extend_from_slice(&e.cluster_offset.to_le_bytes());
        out.extend_from_slice(&e.in_cluster_offset.to_le_bytes());
        out.extend_from_slice(&e.stored_size.to_le_bytes());
        out.extend_from_slice(&e.raw_size.to_le_bytes());
    }
    Ok(out)
}

/// Decodes `TAG_CHUNK_TABLE` value bytes.
pub fn decode_chunk_table(buf: &[u8]) -> Result<Vec<ChunkExtent>, VzError> {
    if buf.len() < 8 {
        return Err(VzError::BufferTooSmall);
    }
    let count = read_le_u32(buf, 0) as usize;
    let needed = 8usize
        .checked_add(
            count
                .checked_mul(ChunkExtent::SIZE)
                .ok_or(VzError::ValueOverflow)?,
        )
        .ok_or(VzError::ValueOverflow)?;
    if buf.len() < needed {
        return Err(VzError::BufferTooSmall);
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let off = 8 + i * ChunkExtent::SIZE;
        out.push(ChunkExtent {
            cluster_offset: read_le_u64(buf, off),
            in_cluster_offset: read_le_u32(buf, off + 8),
            stored_size: read_le_u64(buf, off + 12),
            raw_size: read_le_u64(buf, off + 20),
        });
    }
    Ok(out)
}

/// Optional per-cluster analytical column stats in `TAG_DATA_MANIFEST`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColChunkStats {
    pub col_schema_id: u32,
    pub row_count: u64,
    pub null_count: u64,
    pub min_bytes: Vec<u8>,
    pub max_bytes: Vec<u8>,
}

/// Fixed 32-byte header of `TAG_DATA_MANIFEST` inside a cluster body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataManifestHeader {
    pub entry_id: u64,
    pub raw_size: u64,
    pub stored_size: u64,
    pub payload_crc32c: u32,
    pub manifest_flags: u16,
    pub payload_rel_off: u16,
}

impl DataManifestHeader {
    pub const SIZE: usize = 32;

    pub fn from_bytes(buf: &[u8]) -> Result<Self, VzError> {
        if buf.len() < Self::SIZE {
            return Err(VzError::BufferTooSmall);
        }
        Ok(Self {
            entry_id: read_le_u64(buf, 0),
            raw_size: read_le_u64(buf, 8),
            stored_size: read_le_u64(buf, 16),
            payload_crc32c: read_le_u32(buf, 24),
            manifest_flags: read_le_u16(buf, 28),
            payload_rel_off: read_le_u16(buf, 30),
        })
    }

    pub fn write_bytes(&self, dst: &mut [u8]) -> Result<(), VzError> {
        if dst.len() < Self::SIZE {
            return Err(VzError::BufferTooSmall);
        }
        write_le_u64(dst, 0, self.entry_id);
        write_le_u64(dst, 8, self.raw_size);
        write_le_u64(dst, 16, self.stored_size);
        write_le_u32(dst, 24, self.payload_crc32c);
        write_le_u16(dst, 28, self.manifest_flags);
        write_le_u16(dst, 30, self.payload_rel_off);
        Ok(())
    }

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut out = [0u8; Self::SIZE];
        let _ = self.write_bytes(&mut out);
        out
    }
}

/// Decodes optional column stats from a `TAG_DATA_MANIFEST` value slice.
pub fn decode_manifest_col_stats(val: &[u8]) -> Result<Option<ColChunkStats>, VzError> {
    let hdr = DataManifestHeader::from_bytes(val)?;
    if (hdr.manifest_flags & 1) == 0 {
        return Ok(None);
    }
    let rel = hdr.payload_rel_off as usize;
    if rel > val.len() || rel < DataManifestHeader::SIZE + 20 {
        return Err(VzError::BadFormat);
    }
    let s = &val[DataManifestHeader::SIZE..rel];
    let col_schema_id = read_le_u32(s, 0);
    let row_count = read_le_u64(s, 4);
    let null_count = read_le_u64(s, 12);
    let (min_b, r1) = read_lp_bytes(&s[20..])?;
    let (max_b, _) = read_lp_bytes(r1)?;
    Ok(Some(ColChunkStats {
        col_schema_id,
        row_count,
        null_count,
        min_bytes: min_b.to_vec(),
        max_bytes: max_b.to_vec(),
    }))
}

/// Trailing root fallback index stored inside `TAG_ROOT_FALLBACK` (`32` bytes + optional embedded root).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootFallback {
    pub stream_generation: u64,
    pub total_entries: u64,
    pub root_cluster_off: u64,
    pub root_entry_count: u32,
    pub tree_height: u8,
    pub hash_algo: u8,
    pub embedded_root: Option<Vec<u8>>,
}

/// Encodes `TAG_ROOT_FALLBACK` value bytes.
pub fn encode_root_fallback(fb: &RootFallback) -> Vec<u8> {
    let flags: u16 = if fb.embedded_root.is_some() { 1 } else { 0 };
    let extra = fb.embedded_root.as_ref().map_or(0, Vec::len);
    let mut out = Vec::with_capacity(32 + extra);
    out.extend_from_slice(&fb.stream_generation.to_le_bytes());
    out.extend_from_slice(&fb.total_entries.to_le_bytes());
    out.extend_from_slice(&fb.root_cluster_off.to_le_bytes());
    out.extend_from_slice(&fb.root_entry_count.to_le_bytes());
    out.push(fb.tree_height);
    out.push(fb.hash_algo);
    out.extend_from_slice(&flags.to_le_bytes());
    if let Some(ref root) = fb.embedded_root {
        out.extend_from_slice(root);
    }
    out
}

/// Decodes `TAG_ROOT_FALLBACK` value bytes.
pub fn decode_root_fallback(buf: &[u8]) -> Result<RootFallback, VzError> {
    if buf.len() < 32 {
        return Err(VzError::BufferTooSmall);
    }
    let flags = read_le_u16(buf, 30);
    let embedded_root = if (flags & 1) != 0 {
        Some(buf[32..].to_vec())
    } else {
        None
    };
    Ok(RootFallback {
        stream_generation: read_le_u64(buf, 0),
        total_entries: read_le_u64(buf, 8),
        root_cluster_off: read_le_u64(buf, 16),
        root_entry_count: read_le_u32(buf, 24),
        tree_height: buf[28],
        hash_algo: buf[29],
        embedded_root,
    })
}

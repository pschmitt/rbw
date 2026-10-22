use zeroize::Zeroize as _;

pub const CAPACITY: usize = 4096;

static REGION_LOCK_WORKS: std::sync::OnceLock<bool> =
    std::sync::OnceLock::new();

pub struct Vec {
    // Field order matters: struct fields are dropped in declaration order,
    // and the lock guard must be dropped (munlock) while `data` is still
    // allocated. With the reverse order, the allocator may return the freed
    // pages to the OS before munlock runs (musl's mallocng does), munlock
    // then fails with ENOMEM, and region's LockGuard::drop panics.
    _lock: Option<region::LockGuard>,
    data: Buffer,
}

type Bytes = arrayvec::ArrayVec<u8, CAPACITY>;

enum Buffer {
    Heap(Box<Bytes>),
    Aligned(AlignedBuffer),
}

// Page-aligned, padded allocations keep strict locks on separate pages.
// mlock/munlock are not reference-counted: two ordinary heap allocations
// sharing a page could otherwise unlock each other's live password bytes.
struct AlignedBuffer {
    pointer: std::ptr::NonNull<Bytes>,
    layout: std::alloc::Layout,
}

// SAFETY: this uniquely owns a Bytes allocation; access requires the same
// shared/mutable borrows as Box<Bytes>, which is itself Send + Sync.
unsafe impl Send for AlignedBuffer {}
unsafe impl Sync for AlignedBuffer {}

impl AlignedBuffer {
    fn new() -> std::io::Result<Self> {
        let layout = std::alloc::Layout::from_size_align(
            std::mem::size_of::<Bytes>(),
            region::page::size(),
        )
        .map_err(std::io::Error::other)?
        .pad_to_align();
        // SAFETY: layout is nonzero and valid. The allocation is initialized
        // before any reference is created, and freed with this exact layout.
        #[allow(
            clippy::cast_ptr_alignment,
            reason = "alloc honors the page-aligned Layout, which exceeds Bytes alignment"
        )]
        let pointer = unsafe { std::alloc::alloc(layout) }.cast::<Bytes>();
        let Some(pointer) = std::ptr::NonNull::new(pointer) else {
            return Err(std::io::Error::other(
                "could not allocate password buffer",
            ));
        };
        unsafe {
            pointer.as_ptr().write(Bytes::new());
        }
        Ok(Self { pointer, layout })
    }
}

impl Drop for AlignedBuffer {
    fn drop(&mut self) {
        // SAFETY: Vec wipes the initialized buffer before this field drops.
        // The pointer still uniquely owns the original allocation.
        unsafe {
            std::ptr::drop_in_place(self.pointer.as_ptr());
            std::alloc::dealloc(self.pointer.as_ptr().cast(), self.layout);
        }
    }
}

impl std::ops::Deref for Buffer {
    type Target = Bytes;
    fn deref(&self) -> &Bytes {
        match self {
            Self::Heap(bytes) => bytes,
            // SAFETY: pointer is initialized and live for this borrow.
            Self::Aligned(bytes) => unsafe { bytes.pointer.as_ref() },
        }
    }
}
impl std::ops::DerefMut for Buffer {
    fn deref_mut(&mut self) -> &mut Bytes {
        match self {
            Self::Heap(bytes) => bytes,
            // SAFETY: &mut self guarantees unique access to this allocation.
            Self::Aligned(bytes) => unsafe { bytes.pointer.as_mut() },
        }
    }
}

impl Default for Vec {
    fn default() -> Self {
        let data = Buffer::Heap(Box::new(Bytes::new()));
        let lock = match REGION_LOCK_WORKS.get() {
            Some(true) => {
                Some(region::lock(data.as_ptr(), data.capacity()).unwrap())
            }
            Some(false) => None,
            None => match region::lock(data.as_ptr(), data.capacity()) {
                Ok(lock) => {
                    let _ = REGION_LOCK_WORKS.set(true);
                    Some(lock)
                }
                Err(e) => {
                    if REGION_LOCK_WORKS.set(false).is_ok() {
                        eprintln!("failed to lock memory region: {e}");
                    }
                    None
                }
            },
        };
        Self { data, _lock: lock }
    }
}

impl Vec {
    /// Allocate locked memory, failing instead of silently allowing swapping.
    pub fn try_new() -> std::io::Result<Self> {
        let data = Buffer::Aligned(AlignedBuffer::new()?);
        let lock = region::lock(data.as_ptr(), data.capacity())
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        Ok(Self {
            data,
            _lock: Some(lock),
        })
    }

    pub fn new() -> Self {
        Self::default()
    }

    pub fn data(&self) -> &[u8] {
        self.data.as_slice()
    }

    pub fn data_mut(&mut self) -> &mut [u8] {
        self.data.as_mut_slice()
    }

    pub fn zero(&mut self) {
        self.truncate(0);
        self.data.extend(std::iter::repeat_n(0, CAPACITY));
    }

    pub fn extend(&mut self, it: impl Iterator<Item = u8>) {
        self.data.extend(it);
    }

    pub fn truncate(&mut self, len: usize) {
        if len < self.data.len() {
            self.data.as_mut_slice()[len..].zeroize();
        }
        self.data.truncate(len);
    }
}

impl Drop for Vec {
    fn drop(&mut self) {
        self.zero();
        (*self.data).zeroize();
    }
}

impl Clone for Vec {
    fn clone(&self) -> Self {
        let mut new_vec = Self::new();
        new_vec.extend(self.data().iter().copied());
        new_vec
    }
}

#[derive(Clone)]
pub struct Password {
    password: Vec,
}

impl Password {
    pub fn new(password: Vec) -> Self {
        Self { password }
    }

    pub fn password(&self) -> &[u8] {
        self.password.data()
    }
}

#[derive(Clone)]
pub struct Keys {
    keys: Vec,
}

impl Keys {
    pub fn new(keys: Vec) -> Self {
        Self { keys }
    }

    pub fn enc_key(&self) -> &[u8] {
        &self.keys.data()[0..32]
    }

    pub fn mac_key(&self) -> &[u8] {
        &self.keys.data()[32..64]
    }
}

#[derive(Clone)]
pub struct PasswordHash {
    hash: Vec,
}

impl PasswordHash {
    pub fn new(hash: Vec) -> Self {
        Self { hash }
    }

    pub fn hash(&self) -> &[u8] {
        self.hash.data()
    }
}

#[derive(Clone)]
pub struct PrivateKey {
    private_key: Vec,
}

impl PrivateKey {
    pub fn new(private_key: Vec) -> Self {
        Self { private_key }
    }

    pub fn private_key(&self) -> &[u8] {
        self.private_key.data()
    }
}

#[derive(Clone)]
pub struct ApiKey {
    client_id: Password,
    client_secret: Password,
}

impl ApiKey {
    pub fn new(client_id: Password, client_secret: Password) -> Self {
        Self {
            client_id,
            client_secret,
        }
    }

    pub fn client_id(&self) -> &[u8] {
        self.client_id.password()
    }

    pub fn client_secret(&self) -> &[u8] {
        self.client_secret.password()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_buffers_own_disjoint_pages_and_wipe_removed_bytes() {
        let mut first = Vec::try_new().unwrap();
        let second = Vec::try_new().unwrap();
        let Buffer::Aligned(first_buffer) = &first.data else {
            panic!("expected strict buffer")
        };
        let Buffer::Aligned(second_buffer) = &second.data else {
            panic!("expected strict buffer")
        };
        let page = region::page::size();
        let start = first_buffer.pointer.as_ptr().addr();
        let other = second_buffer.pointer.as_ptr().addr();
        assert_eq!(start % page, 0);
        assert_eq!(other % page, 0);
        assert!(
            start + first_buffer.layout.size() <= other
                || other + second_buffer.layout.size() <= start
        );
        first.extend(b"dummy input".iter().copied());
        let pointer = first.data().as_ptr();
        first.truncate(5);
        // SAFETY: allocation remains live; truncate wipes these initialized
        // u8 slots before shrinking the logical ArrayVec length.
        let removed =
            unsafe { std::slice::from_raw_parts(pointer.add(5), 6) };
        assert!(removed.iter().all(|byte| *byte == 0));
    }
}

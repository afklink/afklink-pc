//! Shared plain data types passed between capture, encode and transport.

/// A captured frame in BGRA8, tightly packed (no row padding), top-down.
#[derive(Clone)]
pub struct Frame {
    /// BGRA pixels, `width * height * 4` bytes.
    pub data: Vec<u8>,
    pub width: u32,
    pub height: u32,
    /// Monotonic capture timestamp in milliseconds (from session start).
    pub timestamp_ms: u64,
}

impl std::fmt::Debug for Frame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Frame")
            .field("width", &self.width)
            .field("height", &self.height)
            .field("timestamp_ms", &self.timestamp_ms)
            .field("bytes", &self.data.len())
            .finish()
    }
}

/// An encoded H.264 access unit in Annex-B form (start-code prefixed NALs).
#[derive(Clone)]
pub struct EncodedFrame {
    pub data: Vec<u8>,
    pub is_keyframe: bool,
    pub timestamp_ms: u64,
}

impl std::fmt::Debug for EncodedFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncodedFrame")
            .field("is_keyframe", &self.is_keyframe)
            .field("timestamp_ms", &self.timestamp_ms)
            .field("bytes", &self.data.len())
            .finish()
    }
}

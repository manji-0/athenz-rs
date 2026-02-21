/// Options for building URLs from a base URL and path segments.
///
/// The default preserves any existing query/fragment and does not
/// trim trailing empty path segments.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct BuildUrlOptions {
    /// When true, clear any existing query string on the base URL.
    pub clear_query: bool,
    /// When true, clear any existing fragment (`#...`) on the base URL.
    pub clear_fragment: bool,
    /// When true, drop a trailing empty path segment before appending segments.
    pub pop_if_empty: bool,
}

impl BuildUrlOptions {
    /// Preset for sync clients.
    ///
    /// Sync and async clients should construct request URLs identically from the
    /// provided base URL: drop query/fragment and trim a trailing empty segment.
    pub const SYNC_CLIENT: Self = Self {
        clear_query: true,
        clear_fragment: true,
        pop_if_empty: true,
    };

    /// Default options used when constructing request URLs.
    #[cfg_attr(not(feature = "async-client"), allow(dead_code))]
    pub const REQUEST: Self = Self {
        clear_query: true,
        clear_fragment: true,
        pop_if_empty: true,
    };
}

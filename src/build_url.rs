/// Options for building URLs from a base URL and path segments.
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
    /// Default options used when constructing request URLs.
    #[cfg_attr(not(feature = "async-client"), allow(dead_code))]
    pub const REQUEST: Self = Self {
        clear_query: true,
        clear_fragment: true,
        pop_if_empty: true,
    };
}

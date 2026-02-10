#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct BuildUrlOptions {
    pub clear_query: bool,
    pub clear_fragment: bool,
    pub pop_if_empty: bool,
}

impl BuildUrlOptions {
    #[cfg(feature = "async-client")]
    pub const REQUEST: Self = Self {
        clear_query: true,
        clear_fragment: true,
        pop_if_empty: true,
    };
}

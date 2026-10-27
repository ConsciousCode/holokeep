//! Utility for ergonomically managing canonicity of parsed data.

/// Enum for determining whether a parsed value was canonical, ie it
/// belongs to a restricted subset which can be safely round-tripped.
pub enum Canon<T> {
    /// Canonical
    Can(T),
    /// Non-canonical
    Non(T),
}

impl<T> Canon<T> {
    /// Construct the canon directly.
    pub fn new(value: T, canon: bool) -> Self {
        if canon { Canon::Can(value) }
        else { Canon::Non(value) }
    }

    /// Construct the canon from a parts tuple.
    pub fn from_parts((value, canon): (T, bool)) -> Self {
        Self::new(value, canon)
    }

    /// Decompose the canon into value and canonicity.
    pub fn into_parts(self) -> (T, bool) {
        match self {
            Self::Can(v) => (v, true),
            Self::Non(v) => (v, false),
        }
    }

    /// Construct a new value using the wrapped value and wrap it in the canon.
    pub fn map<U>(self, new: impl FnOnce(T) -> U) -> Canon<U> {
        let (value, canon) = self.into_parts();
        Canon::new(new(value), canon)
    }

    /// Join the canonicity of two canons into one as a tuple.
    pub fn zip<U>(self, other: Canon<U>) -> Canon<(T, U)> {
        let (x, xb) = self.into_parts();
        let (y, yb) = other.into_parts();
        Canon::new((x, y), xb && yb)
    }

    /// Get a canon reference.
    pub fn as_ref(&self) -> Canon<&T> {
        match self {
            Self::Can(v) => Canon::Can(v),
            Self::Non(v) => Canon::Non(v),
        }
    }

    /// Get a reference to the inner value.
    pub fn inner(&self) -> &T {
        self.as_ref().into_inner()
    }

    /// Get the value regardless of canonicity.
    pub fn into_inner(self) -> T {
        self.into_parts().0
    }

    /// Return whether the value is canonical.
    pub fn is_canon(&self) -> bool {
        matches!(self, Self::Can(_))
    }
}

impl<T> Canon<Canon<T>> {
    pub fn flatten(self) -> Canon<T> {
        let (inner, inner_canon) = self.into_parts();
        let (value, outer_canon) = inner.into_parts();
        Canon::new(value, inner_canon && outer_canon)
    }
}

impl<T, E> Canon<Result<T, E>> {
    /// Switch positions of nested Canon and Result.
    pub fn transpose(self) -> Result<Canon<T>, E> {
        let canon = self.is_canon();
        self.into_inner().map(|v| Canon::new(v, canon))
    }
}

/// An in-progress value, canonical by default, which can be marked as
/// non-canonical in the process of being parsed. It implements Deref
/// because canonicity doesn't matter to access.
pub struct CanonBuilder<T> {
    value: T,
    canonical: bool
}

impl<T> CanonBuilder<T> {
    pub fn new(value: T) -> Self {
        Self { value, canonical: true }
    }

    /// Get whether the Canonical is canon.
    pub fn is_canon(&self) -> bool { self.canonical }

    /// Finish building the value's canonicity.
    pub fn finish(self) -> Canon<T> {
        Canon::new(self.value, self.canonical)
    }

    /// Mark the value as non-canonical.
    pub fn noncanonical(&mut self) {
        self.canonical = false;
    }

    /// Return other's value and conservatively propagate its status.
    pub fn taint<U>(&mut self, other: Canon<U>) -> U {
        let (inner, canon) = other.into_parts();
        self.canonical &= canon;
        inner
    }
}

impl<T> AsRef<T> for CanonBuilder<T> {
    fn as_ref(&self) -> &T {
        &self.value
    }
}

impl<T> AsMut<T> for CanonBuilder<T> {
    fn as_mut(&mut self) -> &mut T {
        &mut self.value
    }
}

impl<T> std::ops::Deref for CanonBuilder<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl<T> std::ops::DerefMut for CanonBuilder<T> {
    fn deref_mut(&mut self) -> &mut T {
        self.as_mut()
    }
}
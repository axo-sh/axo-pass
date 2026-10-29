//! Multi-value registers and their conflict policies.

use std::collections::BTreeMap;
use std::fmt;
use std::marker::PhantomData;

use super::CausalStore;
use super::context::CausalContext;
use super::ids::WriteId;

/// Value of one write, with the data the view and the conflict UI need.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Versioned<T> {
    /// Lamport counter. With the write id, it orders concurrent values.
    pub counter: u64,
    /// Unix seconds by the writer's clock. Display only.
    pub written_at: i64,
    pub value: T,
}

/// Write id, counter, and time of one transaction. Every register the
/// transaction changes is written with the same mint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mint {
    pub write_id: WriteId,
    pub counter: u64,
    pub written_at: i64,
}

/// Conflict policy of a register. Decides the shown value and the conflict
/// handling. It is not serialized.
pub trait Policy {
    const KIND: PolicyKind;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyKind {
    Ask,
    Order,
    Trash,
    Merge,
    Own,
    Stop,
    Rotation,
}

/// Declare a policy marker type for each kind.
macro_rules! policies {
    ($($name:ident),*) => {
        $(
            #[doc = concat!("Marker of [`PolicyKind::", stringify!($name), "`].")]
            pub enum $name {}

            impl Policy for $name {
                const KIND: PolicyKind = PolicyKind::$name;
            }
        )*
    };
}

policies!(Ask, Order, Trash, Merge, Own, Stop, Rotation);

/// Multi-value register. Concurrent writes coexist.
///
/// `Clone`, `PartialEq`, `Eq`, `Debug`, and `Default` are written by hand, so
/// the policy markers need no bounds.
pub struct MvRegister<T, P: Policy> {
    values: BTreeMap<WriteId, Versioned<T>>,
    policy: PhantomData<fn() -> P>,
}

impl<T, P: Policy> MvRegister<T, P> {
    /// Replace every value with `value`, written by `mint`.
    pub fn write(&mut self, mint: &Mint, value: T) {
        self.values.clear();
        self.values.insert(
            mint.write_id,
            Versioned {
                counter: mint.counter,
                written_at: mint.written_at,
                value,
            },
        );
    }

    /// Value written by `id`.
    pub fn get(&self, id: WriteId) -> Option<&Versioned<T>> {
        self.values.get(&id)
    }

    /// Values by write id.
    pub fn values(&self) -> impl Iterator<Item = (WriteId, &Versioned<T>)> {
        self.values.iter().map(|(id, value)| (*id, value))
    }
}

impl<T, P: Policy> CausalStore for MvRegister<T, P> {
    fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    fn each_value(&self, f: &mut dyn FnMut(WriteId, u64)) {
        for (id, value) in &self.values {
            f(*id, value.counter);
        }
    }

    /// Keep a local value if `other` holds its write id or `other_ctx` does
    /// not cover it. Then add each value of `other` that `ctx` does not cover.
    fn join(&mut self, ctx: &CausalContext, other: Self, other_ctx: &CausalContext) {
        let other_values = other.values;
        self.values
            .retain(|id, _| other_values.contains_key(id) || !other_ctx.covers(*id));
        for (id, value) in other_values {
            if !ctx.covers(id) {
                self.values.entry(id).or_insert(value);
            }
        }
    }
}

impl<T, P: Policy> Default for MvRegister<T, P> {
    fn default() -> Self {
        Self {
            values: BTreeMap::new(),
            policy: PhantomData,
        }
    }
}

impl<T: Clone, P: Policy> Clone for MvRegister<T, P> {
    fn clone(&self) -> Self {
        Self {
            values: self.values.clone(),
            policy: PhantomData,
        }
    }
}

impl<T: PartialEq, P: Policy> PartialEq for MvRegister<T, P> {
    fn eq(&self, other: &Self) -> bool {
        self.values == other.values
    }
}

impl<T: Eq, P: Policy> Eq for MvRegister<T, P> {}

impl<T: fmt::Debug, P: Policy> fmt::Debug for MvRegister<T, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MvRegister")
            .field("policy", &P::KIND)
            .field("values", &self.values)
            .finish()
    }
}

/*
 *
 * Copyright 2026 gRPC authors.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 */

use std::any::Any;
use std::mem::MaybeUninit;

use bumpalo::Bump;
use bumpalo::boxed::Box as BumpBox;

/// An arena-allocated box whose lifetime has been erased to `'static`.
///
/// # Invariant
///
/// The `'static` is forged: the allocation lives exactly as long as the [`Bump`]
/// it was made in, so every `ArenaBox` must be dropped before that arena is
/// reset or dropped. Soundness rests on [`CallAttributes`]' field order and
/// `Drop` impl, which tear down every box while the arena is still valid.
type ArenaBox<T> = BumpBox<'static, T>;

/// A single type-erased attribute value, stored in a [`CallAttributes`] arena.
type ErasedAttr = ArenaBox<dyn CloneableAny>;

/// Type-erasure trait for stored attributes, used in place of
/// [`Any`] so that the concrete type's [`Clone`] impl stays reachable
/// through the trait object's vtable.
trait CloneableAny: Any + Send {
    /// Upcasts to `dyn Any` so callers can `downcast_ref`.
    fn as_any(&self) -> &dyn Any;

    /// Mutable counterpart of [`as_any`](Self::as_any), for `downcast_mut`.
    fn as_any_mut(&mut self) -> &mut dyn Any;

    /// Clones `self` into `arena`, preserving the concrete type.
    ///
    /// # Invariant
    ///
    /// The returned box points into `arena`, despite the `'static` in
    /// [`ErasedAttr`]. The caller must store it only in the [`CallAttributes`]
    /// that owns `arena`, so that it is dropped before the arena is.
    fn clone_into_arena(&self, arena: &Bump) -> ErasedAttr;
}

impl<T: Any + Send + Clone> CloneableAny for T {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn clone_into_arena(&self, arena: &Bump) -> ErasedAttr {
        box_in(self.clone(), arena)
    }
}

/// Internal node in the chunked singly linked list holding up to `N` attributes.
struct ChunkNode<const N: usize = 10> {
    next: Option<ArenaBox<ChunkNode<N>>>,
    len: usize,
    items: [MaybeUninit<ErasedAttr>; N],
}

impl<const N: usize> Drop for ChunkNode<N> {
    fn drop(&mut self) {
        for slot in &mut self.items[..self.len] {
            // SAFETY: Slots 0..self.len were written and initialized during insertion.
            unsafe {
                slot.assume_init_drop();
            }
        }
    }
}

/// Dynamic type map storing call attributes in an arena-backed list.
///
/// Implements `Send` automatically and can be held across `.await` points or
/// transferred across threads.
///
/// Stored types must be [`Clone`], which is what makes the map itself
/// [`Clone`].
///
/// # Thread safety
///
/// This type is currently **not `Sync`**, and the blocker is the arena
/// implementation: [`bumpalo::Bump`] allocates through `&self` and tracks its
/// current chunk in `Cell`s, so it is `!Sync` by construction. Nothing about the
/// attribute map itself requires this.
///
/// # Performance
///
/// At most one value is stored per type. Most operations scan the list, so they
/// are O(n); this is intended for the handful of attributes on a typical call,
/// not for large maps.
///
/// Because the backing store is a bump arena, memory is never reclaimed by
/// individual operations — only [`clear`](Self::clear) or dropping the
/// collection returns it.
///
/// [`Clone`] is a deep copy into a fresh arena, so the two maps share no
/// storage.
pub struct CallAttributes<const N: usize = 10> {
    // IMPORTANT: `head` MUST be declared before `arena`.
    // In Rust, struct fields are dropped in top-to-bottom declaration order.
    // Declaring `head` first guarantees that all linked list nodes and stored
    // attributes are dropped while the arena is still fully allocated and valid.
    //
    // Note this is defence in depth rather than the primary mechanism: the
    // explicit `Drop` impl below already empties `head` before any field is
    // dropped. The ordering is what keeps things sound if that impl is ever
    // removed, or if it unwinds partway through.
    head: Option<ArenaBox<ChunkNode<N>>>,
    arena: Bump,
}

impl CallAttributes {
    /// Creates a new empty `CallAttributes` collection with the default chunk
    /// size and [`DEFAULT_ARENA_CAPACITY`](Self::DEFAULT_ARENA_CAPACITY).
    #[inline]
    pub fn new() -> Self {
        Self::new_chunked()
    }

    /// Creates a new `CallAttributes` collection with default chunk size and an
    /// initial arena capacity in bytes.
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self::with_capacity_chunked(capacity)
    }
}

impl<const N: usize> CallAttributes<N> {
    /// Bytes of arena space requested up front by the no-argument constructors.
    ///
    /// Sized so that a typical call's attributes fit in the arena's very first
    /// chunk, because a second chunk costs an extra `malloc` on insert and an
    /// extra `free` on drop.
    ///
    /// Two things make the effective number larger than it looks, and both are
    /// deliberate:
    ///
    /// - `Bump::new()` (capacity 0) allocates *no* chunk at all; the first
    ///   insert then allocates bumpalo's 448-byte default. Requesting capacity
    ///   here trades that lazy allocation for an eager one of a useful size.
    /// - `Bump::with_capacity` rounds up to a power of two and subtracts its
    ///   chunk footer, so 512 actually yields **960 usable bytes**. The next
    ///   step down (448) is too small: 15 attributes need roughly 712 bytes.
    ///
    /// Benchmarked against 4096 (which yields 8128 usable bytes) in
    /// `benches/call_attributes.rs`; the smaller chunk was 15-30% faster across
    /// the construct-and-drop benchmarks, with no tier spilling into a second
    /// chunk.
    pub const DEFAULT_ARENA_CAPACITY: usize = 512;

    /// Compile-time guard: a chunk of zero slots could never hold an attribute.
    ///
    /// A `const` assertion is only evaluated when the function referencing it is
    /// monomorphized, so it has to be pulled in from every entry point we want
    /// it to fire on. It is referenced from `with_capacity_chunked`, which is
    /// the sole constructor that builds a `Self` (`new_chunked` delegates to
    /// it), making a `CallAttributes<0>` impossible to create outside this
    /// module; and from `push_boxed`, which is where the `items[0]` indexing
    /// actually depends on it.
    ///
    /// These are post-monomorphization errors, so they surface during codegen
    /// (`cargo build`, `cargo test`) rather than under `cargo check`.
    const ASSERT_N_NONZERO: () = assert!(N > 0, "CallAttributes chunk size N must be > 0");

    /// Creates a new empty `CallAttributes` collection with a specified chunk
    /// size `N` and [`DEFAULT_ARENA_CAPACITY`](Self::DEFAULT_ARENA_CAPACITY).
    #[inline]
    pub fn new_chunked() -> Self {
        Self::with_capacity_chunked(Self::DEFAULT_ARENA_CAPACITY)
    }

    /// Creates a new `CallAttributes` collection with a specified chunk size
    /// `N` and initial arena capacity in bytes.
    #[inline]
    pub fn with_capacity_chunked(capacity: usize) -> Self {
        const { Self::ASSERT_N_NONZERO };
        Self {
            arena: Bump::with_capacity(capacity),
            head: None,
        }
    }

    /// Inserts a value of type `T` into the call attributes.
    ///
    /// If an entry of type `T` already exists, it is overwritten in place and
    /// the previous value's destructor is executed immediately.
    ///
    /// Runs in O(n), since it scans for an existing entry of type `T`.
    pub fn insert<T: 'static + Send + Clone>(&mut self, val: T) {
        // Check if type T already exists; if so assign into the existing
        // allocation. Reusing the slot matters: a bump allocator never reclaims
        // memory, so allocating a replacement would strand the old value's bytes
        // and let the arena grow without bound under repeated overwrites.
        let mut cur = self.head.as_deref_mut();
        while let Some(node) = cur {
            for slot in &mut node.items[..node.len] {
                // SAFETY: 0..node.len are initialized.
                let item = unsafe { slot.assume_init_mut() };
                if let Some(existing) = item.as_any_mut().downcast_mut::<T>() {
                    // Assignment drops the previous value in place.
                    *existing = val;
                    return;
                }
            }
            cur = node.next.as_deref_mut();
        }

        self.push_new(val);
    }

    /// Allocates `val` in the arena and appends it, without the duplicate scan.
    ///
    /// The caller guarantees no entry of type `T` exists yet.
    fn push_new<T: 'static + Send + Clone>(&mut self, val: T) {
        let boxed_val = box_in(val, &self.arena);
        self.push_boxed(boxed_val);
    }

    /// Appends an already type-erased value, without the duplicate scan.
    ///
    /// The caller guarantees no entry of the same concrete type exists yet, and
    /// that `boxed` was allocated in `self.arena`.
    fn push_boxed(&mut self, boxed: ErasedAttr) {
        const { Self::ASSERT_N_NONZERO };

        // Append into head node if space remains.
        if let Some(ref mut head) = self.head
            && head.len < N
        {
            let idx = head.len;
            head.items[idx].write(boxed);
            head.len += 1;
            return;
        }

        // Head is full or None: allocate a new chunk node in the arena at the
        // front.
        let next = self.head.take();
        // `alloc_with` lets the node be constructed directly in arena memory,
        // instead of building an N-slot temporary on the stack and copying it.
        let node_ref = self.arena.alloc_with(|| {
            let mut items: [MaybeUninit<ErasedAttr>; N] = [const { MaybeUninit::uninit() }; N];
            items[0].write(boxed);
            ChunkNode {
                next,
                len: 1,
                items,
            }
        });

        // SAFETY: `node_ref` is properly aligned, initialized, and lives in
        // `self.arena`.
        let boxed_node: ArenaBox<ChunkNode<N>> =
            unsafe { BumpBox::from_raw(node_ref as *mut ChunkNode<N>) };

        self.head = Some(boxed_node);
    }

    /// Retrieves an immutable reference to the value of type `T`, if present.
    pub fn get<T: 'static>(&self) -> Option<&T> {
        let mut cur = self.head.as_deref();
        while let Some(node) = cur {
            for slot in &node.items[..node.len] {
                // SAFETY: 0..node.len are initialized.
                let item = unsafe { slot.assume_init_ref() };
                if let Some(val) = item.as_any().downcast_ref::<T>() {
                    return Some(val);
                }
            }
            cur = node.next.as_deref();
        }
        None
    }

    /// Clears all stored attributes, executing their destructors and resetting
    /// the internal arena.
    ///
    /// This is the only way to reclaim arena memory short of dropping the
    /// collection.
    pub fn clear(&mut self) {
        // Order matters: `reset` hands the chunks holding the attributes back
        // to the system allocator, so their destructors have to run first.
        // Swapping these two lines would be a use-after-free.
        self.drop_all_nodes();
        self.arena.reset();
    }

    /// Drops every chunk node, and with it every stored attribute, without
    /// touching the arena.
    fn drop_all_nodes(&mut self) {
        // Takes `next` out of each node before dropping the node, so a deep
        // linked list unwinds in O(1) stack frames rather than recursing once
        // per node.
        // Caveat: if a stored value's destructor panics, the remainder of the
        // chain is torn down by ordinary (recursive) drop glue during unwinding,
        // so the O(1) stack guarantee only holds on the non-panicking path.
        let mut cur = self.head.take();
        while let Some(mut node) = cur {
            cur = node.next.take();
            // `node.next` is now None, so dropping `node` here requires O(1)
            // stack frames.
        }
    }
}

/// Helper to allocate `val` in `arena` and type-erase it into an [`ErasedAttr`].
#[inline]
fn box_in<T: 'static + Send + Clone>(val: T, arena: &Bump) -> ErasedAttr {
    let val_ref: &mut T = arena.alloc(val);
    let any_ref: &mut dyn CloneableAny = val_ref;
    // SAFETY: `any_ref` is allocated in `arena`, properly aligned, initialized,
    // and carries the valid vtable for `dyn CloneableAny` with T's destructor.
    // The `'static` lifetime is forged; see [`ArenaBox`] for what upholds it.
    unsafe { BumpBox::from_raw(any_ref as *mut dyn CloneableAny) }
}

impl<const N: usize> Clone for CallAttributes<N> {
    /// Deep-clones every attribute into a fresh arena.
    ///
    /// Runs in O(n) and performs one arena allocation per attribute; the new
    /// arena is pre-sized from the source so the copy usually needs a single
    /// chunk. The clone is independent: mutating one map never affects the other.
    fn clone(&self) -> Self {
        let mut out = Self::with_capacity_chunked(self.arena.allocated_bytes());

        // Walk the source list and re-erase each value into `out`'s arena.
        // `push_boxed` skips the duplicate scan, which is safe because the
        // source holds at most one value per type, making this O(n) overall.
        //
        // Panic safety: values land in `out` as they are cloned, so if a
        // `T::clone` panics, the already-cloned attributes are dropped by
        // `out`'s destructor during unwinding.
        let mut cur = self.head.as_deref();
        while let Some(node) = cur {
            for slot in &node.items[..node.len] {
                // SAFETY: 0..node.len are initialized.
                let item = unsafe { slot.assume_init_ref() };
                let cloned = item.clone_into_arena(&out.arena);
                out.push_boxed(cloned);
            }
            cur = node.next.as_deref();
        }
        out
    }
}

impl<const N: usize> Default for CallAttributes<N> {
    fn default() -> Self {
        Self::new_chunked()
    }
}

impl<const N: usize> Drop for CallAttributes<N> {
    fn drop(&mut self) {
        // Drop all linked list nodes iteratively to prevent stack overflow,
        // and ensure all attributes are dropped while `self.arena` is still
        // valid. Field `head` is also declared before `arena` for
        // declaration-order drop safety.
        //
        // Deliberately not `clear()`: that would additionally `reset()` the
        // arena, which frees every chunk but the current one and rewinds the
        // bump pointer in that survivor — only for `Bump`'s own destructor to
        // free it a moment later. Same end state, two traversals of the chunk
        // list instead of one. This is purely about wasted work; calling
        // `clear()` here would still be sound.
        self.drop_all_nodes();
    }
}

#[cfg(test)]
mod tests {
    use std::panic::AssertUnwindSafe;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::vec::Vec;

    use super::*;

    #[derive(Debug, PartialEq, Eq, Clone)]
    struct UserId(usize);

    #[derive(Debug, PartialEq, Eq, Clone)]
    struct TraceId(&'static str);

    /// Shared counter of executed destructors, for tests that only care *how
    /// many* values were dropped.
    #[derive(Clone, Default)]
    struct DropCount(Arc<AtomicUsize>);

    impl DropCount {
        fn new() -> Self {
            Self::default()
        }

        /// A value that increments this counter when dropped.
        fn tracked(&self) -> Tracked {
            Tracked(self.0.clone())
        }

        /// How many tracked values have been dropped so far.
        fn get(&self) -> usize {
            self.0.load(Ordering::SeqCst)
        }
    }

    /// Increments the [`DropCount`] it came from when dropped.
    #[derive(Clone)]
    struct Tracked(Arc<AtomicUsize>);

    impl Drop for Tracked {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Shared log of executed destructors, for tests that care *which* values
    /// were dropped, and in what order.
    #[derive(Clone, Default)]
    struct DropLog(Arc<Mutex<Vec<usize>>>);

    impl DropLog {
        fn new() -> Self {
            Self::default()
        }

        /// A value that appends `id` to this log when dropped.
        ///
        /// `TAG` exists only to mint distinct types: [`CallAttributes`] stores
        /// at most one value per type, so a test that needs several logged
        /// values live in one map asks for `tagged::<0>(..)`, `tagged::<1>(..)`
        /// and so on. Reusing a tag targets the same slot, which is how the
        /// overwrite path gets exercised.
        fn tagged<const TAG: usize>(&self, id: usize) -> Logged<TAG> {
            Logged(id, self.0.clone())
        }

        /// Ids recorded so far, in the order their destructors ran.
        fn entries(&self) -> Vec<usize> {
            self.0.lock().unwrap().clone()
        }

        /// Ids recorded so far, sorted — for assertions about *which* values
        /// were dropped, where the order is not deterministic.
        fn sorted(&self) -> Vec<usize> {
            let mut ids = self.entries();
            ids.sort();
            ids
        }
    }

    /// Appends its id to the [`DropLog`] it came from when dropped.
    #[derive(Clone)]
    struct Logged<const TAG: usize>(usize, Arc<Mutex<Vec<usize>>>);

    impl<const TAG: usize> Drop for Logged<TAG> {
        fn drop(&mut self) {
            self.1.lock().unwrap().push(self.0);
        }
    }

    #[test]
    fn insert_and_get() {
        let mut attrs = CallAttributes::new();

        attrs.insert(UserId(42));
        attrs.insert(TraceId("trace-1"));

        assert_eq!(attrs.get::<UserId>(), Some(&UserId(42)));
        assert_eq!(attrs.get::<TraceId>(), Some(&TraceId("trace-1")));
        assert_eq!(attrs.get::<String>(), None);
    }

    #[test]
    fn overwrite_value() {
        let mut attrs = CallAttributes::new();

        attrs.insert(UserId(1));
        assert_eq!(attrs.get::<UserId>(), Some(&UserId(1)));

        // Overwrite existing TypeId in place
        attrs.insert(UserId(2));
        assert_eq!(attrs.get::<UserId>(), Some(&UserId(2)));
    }

    #[test]
    fn multi_chunk_overflow() {
        let mut attrs = CallAttributes::<2>::new_chunked();

        attrs.insert(10u32);
        attrs.insert(20u64);
        attrs.insert("third".to_string()); // Triggers 2nd chunk allocation
        attrs.insert(true);
        attrs.insert(1.5f64); // Triggers 3rd chunk allocation

        assert_eq!(attrs.get::<u32>(), Some(&10));
        assert_eq!(attrs.get::<u64>(), Some(&20));
        assert_eq!(attrs.get::<String>(), Some(&"third".to_string()));
        assert_eq!(attrs.get::<bool>(), Some(&true));
        assert_eq!(attrs.get::<f64>(), Some(&1.5));
        assert_eq!(attrs.get::<i32>(), None);
    }

    #[test]
    fn insert_with_drop_destructor_execution() {
        let drops = DropCount::new();
        {
            let mut attrs = CallAttributes::new();

            // Initial insert
            attrs.insert(drops.tracked());
            assert_eq!(drops.get(), 0);

            // Overwrite triggers the destructor of the first value
            attrs.insert(drops.tracked());
            assert_eq!(drops.get(), 1);
        } // `attrs` drops here, triggering the second value's destructor

        assert_eq!(drops.get(), 2);
    }

    #[test]
    fn all_destructors_run_on_drop() {
        let log = DropLog::new();
        {
            let mut attrs = CallAttributes::<2>::new_chunked();
            attrs.insert(log.tagged::<0>(1));
            attrs.insert(log.tagged::<1>(2));
            attrs.insert(log.tagged::<2>(3));
        } // drops all tracked items when `attrs` goes out of scope

        assert_eq!(log.sorted(), vec![1, 2, 3]);
    }

    #[test]
    fn overwrite_drops_old_value_and_remaining_on_drop() {
        let log = DropLog::new();
        {
            let mut attrs = CallAttributes::new();
            attrs.insert(log.tagged::<0>(1));
            attrs.insert(log.tagged::<1>(2));

            // Overwrite the first slot with a new value (id: 10). The old value
            // is dropped immediately during the overwrite:
            attrs.insert(log.tagged::<0>(10));
            assert_eq!(log.entries(), vec![1]);
        } // Exits scope: all remaining slots are dropped

        assert_eq!(log.sorted(), vec![1, 2, 10]);
    }

    #[test]
    fn call_attributes_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<CallAttributes>();
    }

    #[test]
    fn deep_list_iterative_drop_no_stack_overflow() {
        // Miri interprets every access with aliasing bookkeeping, so 50_000
        // arena allocations take minutes there. 500 nodes is still far more than
        // enough to blow the stack if the drop ever regresses to recursive glue.
        let depth = if cfg!(miri) { 500 } else { 50_000 };

        let drops = DropCount::new();
        {
            // With N = 1 every push fills a chunk, so each one links a fresh
            // node onto the front: `depth` pushes give a `depth`-deep chain,
            // each node carrying a live item so the teardown also exercises
            // `ChunkNode::drop`'s item loop and not just the chain walk.
            //
            // `push_new` rather than `insert` because all the values share one
            // type: `insert` would find the existing entry and overwrite it in
            // place, leaving the list one node deep. Skipping the scan breaks
            // the usual "at most one value per type" property, which is fine
            // here — nothing in this test looks values up by type.
            let mut attrs = CallAttributes::<1>::new_chunked();
            for _ in 0..depth {
                attrs.push_new(drops.tracked());
            }
            // Dropping `depth` nodes iteratively must succeed without stack overflow:
        }
        assert_eq!(drops.get(), depth);
    }

    #[test]
    fn clear_runs_destructors_and_empties() {
        let drops = DropCount::new();
        let mut attrs = CallAttributes::<2>::new_chunked();
        attrs.insert(drops.tracked());
        attrs.insert(UserId(1));
        attrs.insert(TraceId("t"));

        attrs.clear();

        assert_eq!(drops.get(), 1, "clear must run destructors");
        assert_eq!(attrs.get::<UserId>(), None);
        assert_eq!(attrs.get::<TraceId>(), None);

        // The collection stays usable after `clear`.
        attrs.insert(UserId(2));
        assert_eq!(attrs.get::<UserId>(), Some(&UserId(2)));
    }

    #[test]
    fn clear_with_multi_chunk_arena_runs_destructors() {
        // `Bump::reset` only frees chunks *other than* the current one, so a
        // single-chunk arena never exercises `clear`'s ordering constraint:
        // with nothing deallocated, running the destructors late is harmless.
        // Push enough values to span several chunks so the constraint bites.
        let n = if cfg!(miri) { 500 } else { 5_000 };

        let drops = DropCount::new();
        let mut attrs = CallAttributes::<1>::new_chunked();
        for _ in 0..n {
            attrs.push_new(drops.tracked());
        }

        attrs.clear();

        assert_eq!(drops.get(), n, "clear must run every destructor");
        assert!(attrs.get::<Tracked>().is_none());
    }

    #[test]
    fn zero_sized_type() {
        #[derive(Clone)]
        struct Marker;
        let mut attrs = CallAttributes::new();
        attrs.insert(Marker);
        assert!(attrs.get::<Marker>().is_some());
    }

    #[test]
    fn over_aligned_type() {
        #[repr(align(64))]
        #[derive(Debug, PartialEq, Eq, Clone)]
        struct OverAligned(u8);

        let mut attrs = CallAttributes::new();
        // Insert a 1-byte value first so the bump pointer is misaligned for
        // the next.
        attrs.insert(7u8);
        attrs.insert(OverAligned(9));

        let val = attrs.get::<OverAligned>().unwrap();
        assert_eq!(val, &OverAligned(9));
        assert_eq!(val as *const _ as usize % 64, 0, "alignment not honoured");
    }

    #[test]
    fn overwrite_in_tail_chunk() {
        // With N=2, `u32` ends up in the oldest (tail) chunk, so this exercises
        // the overwrite path across a chunk boundary rather than in the head.
        let mut attrs = CallAttributes::<2>::new_chunked();
        attrs.insert(1u32);
        attrs.insert(2u64);
        attrs.insert(3i8);
        attrs.insert(4i16);
        attrs.insert(5i64);

        attrs.insert(100u32);

        assert_eq!(attrs.get::<u32>(), Some(&100));
        assert_eq!(attrs.get::<u64>(), Some(&2));
        assert_eq!(attrs.get::<i64>(), Some(&5));
    }

    #[test]
    fn overwrite_reuses_arena_slot() {
        // Repeated inserts of the same type must not grow the arena: the value is
        // assigned into the existing allocation.
        let mut attrs = CallAttributes::new();
        attrs.insert(0u64);
        let addr = attrs.get::<u64>().unwrap() as *const u64 as usize;

        for i in 1..1000u64 {
            attrs.insert(i);
        }

        assert_eq!(attrs.get::<u64>(), Some(&999));
        assert_eq!(
            attrs.get::<u64>().unwrap() as *const u64 as usize,
            addr,
            "overwrite must reuse the original arena allocation"
        );
    }

    #[test]
    fn clone_is_deep_and_independent() {
        let mut attrs = CallAttributes::<2>::new_chunked();
        attrs.insert(UserId(1));
        attrs.insert(TraceId("t"));
        attrs.insert("s".to_string());

        let mut cloned = attrs.clone();
        assert_eq!(cloned.get::<UserId>(), Some(&UserId(1)));
        assert_eq!(cloned.get::<TraceId>(), Some(&TraceId("t")));
        assert_eq!(cloned.get::<String>(), Some(&"s".to_string()));

        // Independent storage.
        assert_ne!(
            attrs.get::<String>().unwrap() as *const String,
            cloned.get::<String>().unwrap() as *const String
        );

        cloned.insert(UserId(2));
        assert_eq!(attrs.get::<UserId>(), Some(&UserId(1)));
        assert_eq!(cloned.get::<UserId>(), Some(&UserId(2)));

        // Clone stays usable and keeps deduplicating.
        cloned.insert(UserId(3));
        assert_eq!(cloned.get::<UserId>(), Some(&UserId(3)));
    }

    #[test]
    fn clone_panic_drops_already_cloned_values() {
        // Pins the panic-safety of `Clone`: values are pushed into the new map
        // as they are cloned, so a panicking `T::clone` must leave the partial
        // copy to be torn down by unwinding rather than leaked.
        struct Boom;
        impl Clone for Boom {
            fn clone(&self) -> Self {
                panic!("clone blew up")
            }
        }

        let drops = DropCount::new();
        let mut attrs = CallAttributes::new();
        attrs.insert(drops.tracked());
        attrs.insert(Boom);

        // The tracked value is cloned first (insertion order within the head
        // chunk), so the partial clone owns one live value when `Boom` panics.
        let result = std::panic::catch_unwind(AssertUnwindSafe(|| attrs.clone()));

        assert!(result.is_err(), "clone must propagate the panic");
        assert_eq!(
            drops.get(),
            1,
            "the already-cloned value must be dropped while unwinding"
        );

        // The source is untouched and still usable.
        assert!(attrs.get::<Tracked>().is_some());
        drop(attrs);
        assert_eq!(drops.get(), 2);
    }

    #[test]
    fn clone_runs_destructors_once_per_map() {
        let drops = DropCount::new();
        {
            let attrs = {
                let mut a = CallAttributes::new();
                a.insert(drops.tracked());
                a
            };
            let _c = attrs.clone();
            assert_eq!(drops.get(), 0);
        }
        assert_eq!(drops.get(), 2);
    }

    /// The point of [`CallAttributes::DEFAULT_ARENA_CAPACITY`] is that a typical
    /// call's attributes fit in the arena's first chunk. Spilling into a second
    /// chunk is not a correctness bug, so nothing else in this suite would
    /// notice it — it just quietly costs an extra `malloc` on insert and an
    /// extra `free` on drop, which is the exact cost the tuning exists to avoid.
    #[test]
    fn default_capacity_holds_typical_attributes_in_one_chunk() {
        let mut attrs = CallAttributes::new();
        let initial = attrs.arena.allocated_bytes();
        assert!(
            initial > 0,
            "default constructor should pre-allocate a chunk"
        );

        // 15 attributes, a deliberately generous stand-in for "a handful". With
        // the default N this spans two `ChunkNode`s, so it also covers the
        // node-growth path rather than just the payloads.
        for i in 0..15u64 {
            attrs.push_new(Payload(i, i, i));
        }

        assert_eq!(
            attrs.arena.allocated_bytes(),
            initial,
            "inserting 15 attributes allocated a second arena chunk; either raise \
             DEFAULT_ARENA_CAPACITY or accept the extra malloc/free per call"
        );
    }

    /// A 24-byte payload, at the larger end of what callers realistically store
    /// inline before reaching for a `Box`/`Arc`.
    #[derive(Clone)]
    struct Payload(u64, u64, u64);
}

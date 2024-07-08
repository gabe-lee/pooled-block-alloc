//! Provides a matching List and Slice type (defined by a comptime factory function) that cache a pointer to a common static `BlockAllocator`
//! interface
//!
//! By caching a type-defined static allocator you get the ergonomics of `ArrayList` without the extra memory footprint of caching the allocator
//! pointer in each list instance separately
//!
//! ### IMPORTANT
//! Caller also asserts that the concrete implementation of the `BlockAllocator` will either handle any allocation errors as a `@panic()`,
//! or that no allocation errors will ever occur. Methods that would traditionally return optional errors from the `BlockAllocator`
//! instead use `catch unreachable` or `orelse unreachable` to further improve ergonomics and compiled logic

const std = @import("std");
const mem = std.mem;
const math = std.math;
const assert = std.debug.assert;
const BlockAllocator = @import("./BlockAllocator.zig");
const AllocError = BlockAllocator.AllocError;

pub inline fn define(comptime T: type, comptime allocator_ptr: *BlockAllocator) type {
    return define_with_sentinel_and_align(T, null, null, allocator_ptr);
}

pub inline fn define_with_sentinel(comptime T: type, comptime sentinel: T, comptime allocator_ptr: *BlockAllocator) type {
    return define_with_sentinel_and_align(T, sentinel, null, allocator_ptr);
}

pub inline fn define_with_align(comptime T: type, comptime alignment: ?u29, comptime allocator_ptr: *BlockAllocator) type {
    return define_with_sentinel_and_align(T, null, alignment, allocator_ptr);
}

pub fn define_with_sentinel_and_align(comptime T: type, comptime sentinel: ?T, comptime alignment: ?u29, comptime allocator_ptr: *BlockAllocator) type {
    if (alignment) |a| {
        if (a == @alignOf(T)) {
            return define_with_sentinel_and_align(T, sentinel, null, allocator_ptr);
        }
    }

    const const_align = if (alignment) |a| a else @alignOf(T);
    if (const_align < @alignOf(T)) @compileError("StaticAllocBuffer does not support alignment smaller than @alignOf(T)");
    if (@sizeOf(T) == 0) @compileError("StaticAllocBuffer does not support zero-size types");

    return struct {
        const Self = @This();
        pub const alloc: *BlockAllocator = allocator_ptr;
        const ALIGN: u29 = const_align;
        const LOG2_OF_ALIGN: u8 = @as(u8, math.log2_int(u29, ALIGN));
        const BLANK_ARRAY align(ALIGN) = if (sentinel) [0:sentinel]T{} else [0]T{};
        const BLANK_PTR: Ptr = @constCast(@alignCast((BLANK_ARRAY[0..0]).ptr));
        const BLANK_LIST = List{
            .ptr = BLANK_PTR,
            .len = 0,
            .cap = 0,
        };
        const BLANK_SLICE = Self{
            .ptr = BLANK_PTR,
            .len = 0,
        };

        pub const ZigSlice = eval: {
            if (alignment) |a| {
                if (sentinel) |s| {
                    break :eval [:s]align(a) T;
                } else {
                    break :eval []align(a) T;
                }
            } else {
                if (sentinel) |s| {
                    break :eval [:s]T;
                } else {
                    break :eval []T;
                }
            }
        };
        pub const Ptr = eval: {
            if (alignment) |a| {
                break :eval [*]align(a) T;
            } else {
                break :eval [*]T;
            }
        };
        const AllocPtr = eval: {
            if (alignment) |a| {
                break :eval [*]align(a) u8;
            } else {
                break :eval [*]u8;
            }
        };
        const AllocSlice = eval: {
            if (alignment) |a| {
                break :eval []align(a) u8;
            } else {
                break :eval []u8;
            }
        };

        pub const Slice = struct {
            ptr: Ptr,
            len: usize,

            /// Turn this StaticAllocSlice into its matching StaticAllocList type
            ///
            /// Slice => List
            /// - `.ptr` => `.ptr`
            /// - `.len` => `.len`
            /// - `.len` => `.cap`
            ///
            /// This operation sets this slice to an empty state
            pub fn upgrade_into_list(self: *Slice) List {
                const list = List{
                    .ptr = self.ptr,
                    .cap = self.len,
                    .len = self.len,
                };
                self.* = BLANK_SLICE;
                return list;
            }

            /// Turn this StaticAllocSlice into its matching StaticAllocList type
            ///
            /// Useful if you know some portion of this slice has undefined values
            ///
            /// Slice => List
            /// - `.ptr`     => `.ptr`
            /// - `list_len` => `.len`
            /// - `.len`     => `.cap`
            ///
            /// This operation sets this slice to an empty state
            pub fn upgrade_into_list_partial(self: *Slice, list_len: usize) List {
                assert(list_len <= self.len);
                const list = List{
                    .ptr = self.ptr,
                    .cap = self.len,
                    .len = list_len,
                };
                self.* = BLANK_SLICE;
                return list;
            }

            pub fn take_ownership_same_alloc(same_alloc_slice: ZigSlice) Slice {
                return Slice{
                    .ptr = same_alloc_slice.ptr,
                    .len = same_alloc_slice.len,
                };
            }

            pub fn give_ownership_of_slice(self: *Slice) ZigSlice {
                assert(self.len > 0);
                const ret_slice = self.slice();
                self.* = BLANK_SLICE;
                return ret_slice;
            }

            /// Creates a new slice using the type-defined allocator with a length equal-to
            /// or greater-than the minimum requested
            ///
            /// If `len == 0` the pointer references a type-defined const zero-length (with optional sentinel) array
            ///
            /// For a slice with an exact length, use `.create_exact(exact_len)`
            pub fn create_minimum(min_len: usize) Slice {
                if (min_len == 0) {
                    return Slice{
                        .ptr = BLANK_PTR,
                        .len = 0,
                    };
                }
                const alloc_len = type_len_to_alloc_len(min_len);
                const alloc_slice: AllocSlice = @alignCast(alloc.raw_alloc(alloc_len, LOG2_OF_ALIGN, @returnAddress()) orelse unreachable);
                var new = from_alloc_mem(alloc_slice);
                if (sentinel) |s| {
                    new.ptr[new.len] = s;
                }
                return new;
            }

            /// Creates a new slice using the type-defined allocator with an exact length
            ///
            /// If `len == 0` the pointer references a type-defined const zero-length (with optional sentinel) array
            pub fn create_exact(exact_len: usize) Slice {
                var new = Slice.create_minimum(exact_len);
                assert(new.len >= exact_len);
                new.len = exact_len;
                if (sentinel) |s| {
                    new.ptr[new.len] = s;
                }
                return new;
            }

            /// Resizes slice using type-defined allocator to a new length greater-than
            /// or equal-to the requested length
            ///
            /// Returns `false` if existing memory pointers were invalidated (underlying memory reallocated),
            /// else `true` if existing memory pointers are still valid (no memory move)
            ///
            /// For a slice with an exact length, you can re-slice the result, or use
            /// `.resize_exact(exact_len)`
            pub fn resize_minimum(self: *Slice, new_min_len: usize) bool {
                if (self.len == 0 or self.ptr == BLANK_PTR) {
                    if (new_min_len == 0) {
                        return true;
                    }
                    self.* = Slice.create_minimum(new_min_len);
                    return false;
                }
                if (new_min_len == 0) {
                    self.release();
                    return false;
                }
                const alloc_mem = self.to_alloc_mem();
                const new_alloc_len = type_len_to_alloc_len(new_min_len);
                if (alloc.raw_resize(alloc_mem, LOG2_OF_ALIGN, new_alloc_len, @returnAddress())) |new_real_len| {
                    self.len = alloc_len_to_type_len(new_real_len);
                    if (sentinel) |s| {
                        self.ptr[self.len] = s;
                    }
                    return true;
                }
                const new = Slice.create_minimum(new_min_len);
                const least_len = @min(self.len, new.len);
                @memcpy(new.ptr[0..least_len], self.ptr[0..least_len]);
                self.release();
                self.* = new;
                return false;
            }

            /// Resizes slice using type-defined allocator to a new exact length
            ///
            /// Returns `false` if existing memory pointers were invalidated (underlying memory reallocated),
            /// else `true` if existing memory pointers are still valid (no memory move)
            pub fn resize_exact(self: *Slice, exact_len: usize) bool {
                const resize_result = self.resize_minimum(exact_len);
                self.len = exact_len;
                if (sentinel) |s| {
                    self.ptr[self.len] = s;
                }
                return resize_result;
            }

            /// Attempts to resize slice using type-defined allocator to a new length greater-than
            /// or equal-to the requested length, WITHOUT moving the memory address
            ///
            /// Returns `false` if resize could not be completed without moving the memory address,
            /// else `true` if resize without move was successful
            ///
            /// For a slice with an exact length, you can re-slice the result, or use
            /// `.resize_exact_no_move(exact_len)`
            pub fn resize_minimum_no_move(self: *Slice, new_min_len: usize) bool {
                if ((self.len == 0 or self.ptr == BLANK_PTR) and new_min_len == 0) {
                    return true;
                }
                if (new_min_len == 0) {
                    return false;
                }
                const alloc_mem = self.to_alloc_mem();
                const new_alloc_len = type_len_to_alloc_len(new_min_len);
                if (alloc.raw_resize(alloc_mem, LOG2_OF_ALIGN, new_alloc_len, @returnAddress())) |new_real_len| {
                    self.len = alloc_len_to_type_len(new_real_len);
                    if (sentinel) |s| {
                        self.ptr[self.len] = s;
                    }
                    return true;
                }
                return false;
            }

            /// Resizes slice using type-defined allocator to a new exact length,
            /// WITHOUT moving the underlying memory address
            ///
            /// Returns `false` if resize could not be completed without moving the memory address,
            /// else `true` if resize without move was successful
            pub fn resize_exact_no_move(self: *Slice, exact_len: usize) bool {
                const resize_success = self.resize_minimum_no_move(exact_len);
                if (resize_success) {
                    self.len = exact_len;
                    if (sentinel) |s| {
                        self.ptr[self.len] = s;
                    }
                }
                return resize_success;
            }

            /// Releases the memory using the type-defined allocator, invalidating any element pointers
            ///
            /// Does nothing if `len == 0` or the pointer references the type-defined const zero-length array
            ///
            /// The slice struct can still be re-used by calling `slice.resize(new_len)` to allocate a new piece of memory for it
            pub fn release(self: *Slice) void {
                if (self.len == 0 or self.ptr == BLANK_PTR) return;
                const alloc_slice = self.to_alloc_mem();
                alloc.raw_free(alloc_slice, LOG2_OF_ALIGN, @returnAddress());
                self.len = 0;
                self.ptr = BLANK_PTR;
            }

            /// Creates a new slice referencing new memory that holds all the same values as the this one
            pub fn clone(self: *Slice) Slice {
                const new = Slice.create_exact(self.len);
                @memcpy(new.ptr[0..self.len], self.ptr[0..self.len]);
                return new;
            }

            /// Returns the normal Zig slice using the pointer and length
            pub inline fn slice(self: *Slice) ZigSlice {
                return self.ptr[0..self.len];
            }

            inline fn to_alloc_mem(self: *Slice) AllocSlice {
                const byte_ptr: AllocPtr = @ptrCast(@alignCast(self.ptr));
                return byte_ptr[0..type_len_to_alloc_len(self.len)];
            }

            inline fn from_alloc_mem(alloc_slice: AllocSlice) Slice {
                const type_ptr: Ptr = @ptrCast(@alignCast(alloc_slice.ptr));
                const type_len = alloc_len_to_type_len(alloc_slice.len);
                return Slice{
                    .ptr = type_ptr,
                    .len = type_len,
                };
            }

            inline fn type_len_to_alloc_len(len: usize) usize {
                const type_len = if (sentinel != null) len + 1 else len;
                return (type_len * @sizeOf(T));
            }

            inline fn alloc_len_to_type_len(alloc_len: usize) usize {
                const non_sentinel_len = if (sentinel != null) alloc_len - @sizeOf(T) else alloc_len;
                return (non_sentinel_len / @sizeOf(T));
            }
        };

        pub const List = struct {
            ptr: Ptr,
            len: usize,
            cap: usize,

            /// Create a new StaticAllocList in an un-allocated state
            pub inline fn create() List {
                return BLANK_LIST;
            }

            /// Create a new StaticAllocList with at least `min_cap` capacity, possibly more
            pub fn create_with_capacity(min_cap: usize) List {
                if (min_cap == 0) {
                    return BLANK_LIST;
                }
                const q_slice = Slice.create_minimum(min_cap);
                return q_slice.upgrade_into_list_partial(0);
            }

            /// Releases the memory using the type-defined allocator, invalidating any element pointers
            ///
            /// Does nothing if `cap == 0` or the pointer references the type-defined const zero-length array
            ///
            /// The list struct can still be re-used by adding new elements to it, which will begin a new allocation
            pub fn release(self: *List) void {
                var q_slice = self.downgrade_into_slice();
                q_slice.release();
            }

            pub fn take_ownership_same_alloc(same_alloc_slice: ZigSlice) List {
                return List{
                    .ptr = same_alloc_slice.ptr,
                    .len = same_alloc_slice.len,
                    .cap = same_alloc_slice.len,
                };
            }

            pub fn give_ownership_of_slice(self: *List) ZigSlice {
                assert(self.len > 0);
                const ret_slice = self.slice();
                self.* = BLANK_LIST;
                return ret_slice;
            }

            /// Turn this StaticAllocList into its matching StaticAllocSlice type
            ///
            /// Caller assumes responsibility for dealing with undefined values
            /// located between len and cap
            ///
            /// List => Slice
            /// - `.ptr` => `.ptr`
            /// - `.len` =>  ----------
            /// - `.cap` => `.len`
            ///
            /// This operation sets this slice to an empty state
            pub fn downgrade_into_slice(self: *List) Slice {
                const q_slice = self.to_quick_slice();
                self.* = BLANK_LIST;
                return q_slice;
            }

            /// Turn this StaticAllocList into its matching StaticAllocSlice type
            ///
            /// Resizes resulting slice to only have indexes below `.len`,
            /// possibly invalidating pointers to its memory or elements
            ///
            /// List => Slice
            /// - `.ptr` => `.ptr`
            /// - `.len` => `.len`
            /// - `.cap` =>  ----------
            ///
            /// This operation sets this slice to an empty state
            pub fn downgrade_into_slice_partial(self: *List) Slice {
                var q_slice = self.to_quick_slice();
                _ = q_slice.resize_exact(self.len);
                self.* = BLANK_LIST;
                return q_slice;
            }

            /// Creates a new list referencing new memory that holds all the same values as this one
            pub fn clone(self: *const List) List {
                const new_slice = Slice.create_exact(self.cap);
                @memcpy(new_slice.ptr[0..self.len], self.ptr[0..self.len]);
                return new_slice.upgrade_into_list_partial(self.len);
            }

            /// Returns the normal Zig slice using the pointer and length
            pub inline fn slice(self: *List) ZigSlice {
                if (sentinel) |s| {
                    self.ptr[self.len] = s;
                }
                return self.ptr[0..self.len];
            }

            /// Insert `item` at index `idx`. Moves all elements at indices >= `idx`
            /// up in an O(N) operation, invalidating eny element pointers to them.
            ///
            /// May invalidate all element pointers if reallocation of list was necessary
            pub fn insert(self: *List, idx: usize, item: T) void {
                const dst = self.insert_slots(idx, 1);
                dst[0] = item;
            }

            /// Insert `item` at index `idx`. Moves all elements at indices >= `idx`
            /// up in an O(N) operation, invalidating eny element pointers to them.
            ///
            /// Never invalidates element pointers below `idx`
            pub fn insert_assume_capacity(self: *List, idx: usize, item: T) void {
                const dst = self.insert_slots_assume_capacity(idx, 1);
                dst[0] = item;
            }

            /// Add `count` undefined new elements at position `idx`,
            /// and return a slice pointing to the newly allocated elements.
            ///
            /// Always invalidates pointers to elements at `idx` or higher,
            /// may invalidate all element pointers if reallocation is needed
            pub fn insert_slots(self: *List, idx: usize, count: usize) []T {
                assert(idx <= self.len);
                const new_min_len = self.len + count;

                if (self.cap >= new_min_len) return self.insert_slots_assume_capacity(idx, count);
                if (self.ptr != BLANK_PTR and self.cap != 0 and self.len != 0) {
                    var q_slice = self.to_quick_slice();
                    if (q_slice.resize_minimum_no_move(new_min_len)) {
                        self.from_quick_slice(q_slice);
                        return self.insert_slots_assume_capacity(idx, count);
                    }
                }

                const new_slice = Slice.create_minimum(new_min_len);
                const to_move_up = self.ptr[idx..self.len];
                @memcpy(new_slice.ptr[0..idx], self.ptr[0..idx]);
                @memcpy(new_slice.ptr[idx + count ..][0..to_move_up.len], to_move_up);
                self.release();
                self.from_quick_slice_cap_always_larger(new_slice);
                self.len = new_min_len;
                return self.ptr[idx .. idx + self.len][0..count];
            }

            /// Add `count` undefined elements at position `idx`,
            /// and return a slice pointing to the newly allocated elements.
            ///
            /// This slice is only valid until another operation causes indexes or list
            /// memory addresses to move
            ///
            /// Always invalidates pointers to elements at `idx` or higher,
            /// but never invalidates memory pointers below `idx`
            pub fn insert_slots_assume_capacity(self: *List, idx: usize, count: usize) []T {
                assert(idx <= self.len);
                const new_len = self.len + count;
                assert(self.cap >= new_len);
                const to_move = self.ptr[idx..self.len];
                self.len = new_len;
                mem.copyBackwards(T, self.ptr[idx + count .. self.len], to_move);
                const result = self.ptr[idx..self.len][0..count];
                return result;
            }

            /// Add slice `items` starting at position `idx`, moving up all elements
            /// at indices >= `idx`
            ///
            /// Always invalidates pointers to elements at `idx` or higher,
            /// may invalidate all element pointers if reallocation is needed
            pub fn insert_slice(self: *List, idx: usize, items: []const T) void {
                const dst = self.insert_slots(idx, items.len);
                @memcpy(dst, items);
            }

            /// Add slice `items` starting at position `idx`, moving up all elements
            /// at indices >= `idx`
            ///
            /// Always invalidates pointers to elements at `idx` or higher,
            /// but never invalidates memory pointers below `idx`
            pub fn insert_slice_assume_capacity(self: *List, idx: usize, items: []const T) void {
                assert(self.len + items.len <= self.cap);
                const dst = self.insert_slots_assume_capacity(idx, items.len);
                @memcpy(dst, items);
            }

            /// Insert a value into the list `count` times starting at `idx`.
            ///
            /// Allocates more memory as necessary.
            ///
            /// Always invalidates pointers to elements at `idx` or higher,
            /// may invalidate all element pointers if reallocation is needed
            pub inline fn insert_n_times(self: *List, idx: usize, value: T, count: usize) void {
                const new_slots = self.insert_slots(idx, count);
                @memset(new_slots, value);
            }

            /// Insert a value into the list `count` times starting at `idx`.
            ///
            /// Always invalidates pointers to elements at `idx` or higher,
            /// but never invalidates memory pointers below `idx`
            pub inline fn insert_n_times_assume_capacity(self: *List, idx: usize, value: T, count: usize) void {
                const new_slots = self.insert_slots_assume_capacity(idx, count);
                @memset(new_slots, value);
            }

            /// Replaces existing range `list[replace_start..replace_start+replace_len]` with
            /// `new_items`, a slice of arbitrary size.
            ///
            /// If `new_items.len` > `replace_len`, all elements >= `replace_start+replace_len` will be moved up,
            /// invalidating element pointers to them
            ///
            /// If `new_items.len` < `replace_len`, all elements >= `replace_start+replace_len` will be moved down,
            /// invalidating element pointers to them
            ///
            /// May invalidate ALL element pointers if reallocation was necessary to hold the new items
            pub fn replace_range(self: *List, replace_start: usize, replace_len: usize, new_items: []const T) void {
                assert(replace_start + replace_len <= self.len);
                if (replace_len == new_items.len) {
                    @memcpy(self.ptr[replace_start..replace_len], new_items);
                    return;
                }
                const new_min_len = self.len - replace_len + new_items.len;

                if (self.cap >= new_min_len)
                    return self.replace_range_assume_capacity(replace_start, replace_len, new_items);

                const q_slice = self.to_quick_slice();
                if (q_slice.resize_minimum_no_move(new_min_len)) {
                    self.from_quick_slice(q_slice);
                    return self.replace_range_assume_capacity(replace_start, replace_len);
                }

                const new_slice = Slice.create_minimum(new_min_len);
                const to_move_up = self.ptr[replace_start + replace_len .. self.len];
                @memcpy(new_slice.ptr[0..replace_start], self.ptr[0..replace_start]);
                @memcpy(new_slice.ptr[replace_start .. replace_start + new_items.len], new_items);
                @memcpy(new_slice.ptr[replace_start + new_items.len .. self.len][0..to_move_up.len], to_move_up);
                self.release();
                self.from_quick_slice_cap_always_larger(new_slice);
                self.len = new_min_len;
                return;
            }

            /// Replaces existing range `list[replace_start..replace_start+replace_len]` with
            /// `new_items`, a slice of arbitrary size.
            ///
            /// If `new_items.len` > `replace_len`, all elements >= `replace_start+replace_len` will be moved up,
            /// invalidating element pointers to them
            ///
            /// If `new_items.len` < `replace_len`, all elements >= `replace_start+replace_len` will be moved down,
            /// invalidating element pointers to them
            ///
            /// Never invalidates element pointers below `replace_start`
            pub fn replace_range_assume_capacity(self: *List, replace_start: usize, replace_len: usize, new_items: []const T) void {
                assert(replace_start + replace_len <= self.len);
                if (replace_len == new_items.len) {
                    @memcpy(self.ptr[replace_start..replace_len], new_items);
                    return;
                }
                const new_len = self.len - replace_len + new_items.len;
                assert(self.cap >= new_len);
                const to_move = self.ptr[replace_start + replace_len .. self.len];
                const copy_dst_start = replace_start + new_items.len;
                const copy_dst_end = copy_dst_start + to_move.len;
                if (new_items.len > replace_len) {
                    mem.copyBackwards(T, self.ptr[copy_dst_start..copy_dst_end], to_move);
                } else {
                    mem.copyForwards(T, self.ptr[copy_dst_start..copy_dst_end], to_move);
                }
                @memcpy(self.ptr[replace_start .. replace_start + new_items.len], new_items);
                self.len = new_len;
                return;
            }

            /// Adds 1 element at the end of the list. Allocates more memory as necessary.
            ///
            /// Invalidates element pointers if additional memory is needed.
            pub fn append(self: *List, item: T) void {
                const new_item_ptr = self.append_slot();
                new_item_ptr.* = item;
            }

            /// Adds 1 element at the end of the list.
            ///
            /// Never invalidates element pointers.
            pub fn append_assume_capacity(self: *List, item: T) void {
                const new_item_ptr = self.append_slot_assume_capacity();
                new_item_ptr.* = item;
            }

            /// Remove the element at index `idx` and shift down all the elements
            /// above it.
            ///
            /// Returns the value removed
            ///
            /// Invalidates element pointers to elements in positions >= `idx`
            pub fn remove(self: *List, idx: usize) T {
                assert(idx < self.len);
                const old_item = self.ptr[idx];
                mem.copyForwards(T, self.ptr[idx..self.len], self.ptr[idx + 1 .. self.len]);
                return old_item;
            }

            /// Remove the element at index `idx` swap the last element into its old idx
            ///
            /// Returns the value removed
            ///
            /// Invalidates element pointers to elements in positions `idx` and `len - 1`
            pub fn swap_remove(self: *List, idx: usize) T {
                assert(idx < self.len);
                if (self.len - 1 == idx) return self.pop();

                const old_item = self.ptr[idx];
                self.ptr[idx] = self.pop();
                return old_item;
            }

            /// Append a slice of items to the end of the list.
            ///
            /// Invalidates all element pointers if additional memory is needed.
            pub fn append_slice(self: *List, items: []const T) void {
                _ = self.ensure_unused_cap(items.len);
                self.append_slice_assume_capacity(items);
            }

            /// Append a slice of items to the end of the list.
            ///
            /// Never invalidates element pointers.
            pub fn append_slice_assume_capacity(self: *List, items: []const T) void {
                const old_len = self.len;
                const new_len = old_len + items.len;
                assert(new_len <= self.cap);
                @memcpy(self.ptr[self.len..self.cap][0..items.len], items);
                self.len = new_len;
            }

            pub const Writer = if (T != u8)
                @compileError("The Writer interface is only defined for an element type of u8 " ++
                    "but the element type of this List is " ++ @typeName(T))
            else
                std.io.Writer(*List, AllocError, write_bytes);

            /// Returns a Writer interface for this list.
            pub inline fn writer(self: *List) Writer {
                return .{ .context = self };
            }

            fn write_bytes(self: *List, m: []const u8) error{OutOfMemory}!usize {
                self.append_slice(m);
                return m.len;
            }

            /// Appends a formatted string to the list
            ///
            /// Only valid when defined element type `T` is `u8`
            pub inline fn append_fmt_string(self: *List, comptime fmt: []const u8, args: anytype) void {
                std.fmt.format(self.writer(), fmt, args) catch unreachable;
            }

            /// Clears list (keeps capacity), appends a formatted string, and returns the resulting byte slice
            ///
            /// Only valid when defined element type `T` is `u8`
            pub inline fn quick_fmt_string(self: *List, comptime fmt: []const u8, args: anytype) []const u8 {
                self.clear();
                std.fmt.format(self.writer(), fmt, args) catch unreachable;
                return self.slice();
            }

            /// Append a value to the list `count` times.
            ///
            /// Allocates more memory as necessary.
            ///
            /// Invalidates all element pointers if additional memory is needed.
            pub inline fn append_n_times(self: *List, value: T, count: usize) void {
                const new_slots = self.append_slots_slice_ptr(count);
                @memset(new_slots, value);
            }

            /// Append a value to the list `count` times.
            ///
            /// Allocates more memory as necessary.
            ///
            /// Never invalidates element pointers.
            pub inline fn append_n_times_assume_capacity(self: *List, value: T, count: usize) void {
                const new_slots = self.append_slots_slice_ptr_assume_capacity(count);
                @memset(new_slots, value);
            }

            /// Resizes list using type-defined allocator to a new capacity greater-than
            /// or equal-to the requested capacity
            ///
            /// Returns `false` if existing memory pointers were invalidated (underlying memory reallocated),
            /// else `true` if existing memory pointers are still valid (no memory move)
            pub fn resize_cap(self: *List, new_len: usize) bool {
                var q_slice = self.to_quick_slice();
                const ptrs_valid = q_slice.resize_minimum(new_len);
                self.from_quick_slice(q_slice);
                return ptrs_valid;
            }

            /// Attempts to resize list using type-defined allocator to a new capacity greater-than
            /// or equal-to the requested capacity, WITHOUT moving the memory address
            ///
            /// Returns `false` if resize could not be completed without moving the memory address,
            /// else `true` if resize without move was successful
            pub fn resize_cap_no_move(self: *List, new_len: usize) bool {
                var q_slice = self.to_quick_slice();
                const success = q_slice.resize_minimum_no_move(new_len);
                self.from_quick_slice(q_slice);
                return success;
            }

            /// Set `len = len - shrink_count`
            ///
            /// Asserts `len >= shrink_count`
            ///
            /// Invalidates all element pointers >= the new len
            pub inline fn shrink_len_by_count(self: *List, shrink_count: usize) void {
                assert(self.len >= shrink_count);
                self.len -= shrink_count;
            }

            /// Set `len = len + grow_count`
            ///
            /// Asserts `cap >= len + grow_count`
            ///
            /// Additional elements should be considered `undefined`
            pub inline fn grow_len_by_count(self: *List, grow_count: usize) void {
                assert(self.cap >= self.len + grow_count);
                self.len += grow_count;
            }

            /// Directly set `len` to new value
            ///
            /// Asserts `new_len <= cap`
            ///
            /// If `new_len < len`, invalidates all element pointers >= `new_len`
            ///
            /// If `new_len > len`, additional elements should be considered `undefined`
            pub inline fn set_len_to(self: *List, new_len: usize) void {
                assert(new_len <= self.cap);
                self.len = new_len;
            }

            /// Set `len = 0` but allow list to keep its capacity for
            /// future use
            ///
            /// Invalidates all element pointers.
            pub inline fn clear(self: *List) void {
                self.len = 0;
            }

            /// Set `len = cap`, additional elements should be considered `undefined`
            pub inline fn grow_len_to_cap(self: *List) void {
                self.len = self.cap;
            }

            /// Checks whether `cap >= new_capacity`, and grows capacity if needed
            ///
            /// Returns `false` if existing memory pointers were invalidated (underlying memory reallocated),
            /// else `true` if existing memory pointers are still valid (no memory move)
            pub inline fn ensure_cap(self: *List, new_capacity: usize) bool {
                if (self.cap >= new_capacity) return true;
                return self.resize_cap(new_capacity);
            }

            /// Checks whether `cap >= new_capacity`, and grows capacity if needed
            ///
            /// Returns `false` if grow could not be completed without moving the memory address,
            /// else `true` if grow without move was successful
            pub inline fn ensure_cap_no_move(self: *List, new_capacity: usize) bool {
                if (self.cap >= new_capacity) return true;
                return self.resize_cap_no_move(new_capacity);
            }

            /// Checks whether `cap >= len + additional_count`, and grows capacity if needed
            ///
            /// Returns `false` if existing memory pointers were invalidated (underlying memory reallocated),
            /// else `true` if existing memory pointers are still valid (no memory move)
            pub inline fn ensure_unused_cap(self: *List, additional_count: usize) bool {
                return self.ensure_cap(self.len + additional_count);
            }

            /// Checks whether `cap >= len + additional_count`, and grows capacity if needed
            ///
            /// Returns `false` if grow could not be completed without moving the memory address,
            /// else `true` if grow without move was successful
            pub inline fn ensure_unused_cap_no_move(self: *List, additional_count: usize) bool {
                return self.ensure_cap_no_move(self.len + additional_count);
            }

            /// Increase length by 1, returning pointer to the new item slot with undefined memory.
            ///
            /// Invalidates all element pointers if additional memory is needed.
            pub fn append_slot(self: *List) *T {
                const newlen = self.len + 1;
                _ = self.ensure_cap(newlen);
                return self.append_slot_assume_capacity();
            }

            /// Increase length by 1, returning pointer to the new item slot with undefined memory.
            ///
            /// Never invalidates element pointers.
            pub inline fn append_slot_assume_capacity(self: *List) *T {
                assert(self.len < self.cap);
                self.len += 1;
                return &self.ptr[self.len - 1];
            }

            /// Increase length by `count`, returning pointer to the new slots with undefined memory as
            /// a pointer to an array.
            ///
            /// Invalidates all element pointers if additional memory is needed.
            pub inline fn append_slots_array_ptr(self: *List, comptime count: usize) *[count]T {
                _ = self.ensure_unused_cap(self.len + count);
                self.append_slots_array_ptr_assume_capacity(count);
            }

            /// Increase length by `count`, returning a pointer to an array referencing the new undefined memory slots.
            ///
            /// Never invalidates element pointers.
            pub fn append_slots_array_ptr_assume_capacity(self: *List, comptime count: usize) *[count]T {
                assert(self.len + count <= self.cap);
                const old_len = self.len;
                self.len += count;
                return self.ptr[old_len..self.len][0..count];
            }

            /// Increase length by `count`, returning a slice referencing the new undefined memory slots.
            ///
            /// Invalidates all element pointers if additional memory is needed.
            pub inline fn append_slots_slice_ptr(self: *List, count: usize) []T {
                _ = self.ensure_unused_cap(self.len + count);
                self.append_slots_array_ptr_assume_capacity(count);
            }

            /// Increase length by `count`, returning a slice referencing the new undefined memory slots.
            ///
            /// Never invalidates element pointers.
            pub fn append_slots_slice_ptr_assume_capacity(self: *List, count: usize) []T {
                assert(self.len + count <= self.cap);
                const old_len = self.len;
                self.len += count;
                return self.ptr[old_len..self.len][0..count];
            }

            /// Remove and return the last element from the list.
            ///
            /// Invalidates element pointers to the removed element.
            pub fn pop(self: *List) T {
                const val = self.ptr[self.len - 1];
                self.len -= 1;
                return val;
            }

            /// Remove and return the last element from the list, or
            /// return `null` if list is empty.
            ///
            /// Invalidates element pointers to the removed element, if any.
            pub inline fn pop_or_null(self: *List) ?T {
                if (self.len == 0) return null;
                return self.pop();
            }

            /// Returns the value of the last element in the list.
            pub inline fn get_last(self: *const List) T {
                const val = self.items[self.len - 1];
                return val;
            }

            /// Returns the value of the last element in the list, or `null` if list is empty.
            pub inline fn get_last_or_null(self: *const List) ?T {
                if (self.len == 0) return null;
                return self.get_last();
            }

            /// Same as `downgrade_into_slice()` but does not erase this list's pointer or size
            ///
            /// Unsafe is misused
            inline fn to_quick_slice(self: *List) Slice {
                const q_slice = Slice{
                    .ptr = self.ptr,
                    .len = self.cap,
                };
                return q_slice;
            }

            /// Same as `downgrade_into_slice_partial()` but does not erase this list's pointer or size
            ///
            /// Unsafe is misused
            inline fn to_quick_slice_partial(self: *List) Slice {
                const q_slice = Slice{
                    .ptr = self.ptr,
                    .len = self.len,
                };
                return q_slice;
            }

            /// Same as `upgrade_from_slice_partial()` but does not erase that slice's pointer or size
            ///
            /// Unsafe is misused
            inline fn from_quick_slice(self: *List, q_slice: Slice) void {
                self.ptr = q_slice.ptr;
                self.cap = q_slice.len;
                if (self.len > self.cap) {
                    self.len = self.cap;
                }
            }

            /// Same as `upgrade_from_slice_partial()` but does not erase that slice's pointer or size
            ///
            /// Unsafe is misused
            inline fn from_quick_slice_cap_always_larger(self: *List, q_slice: Slice) void {
                self.ptr = q_slice.ptr;
                self.cap = q_slice.len;
            }
        };
    };
}

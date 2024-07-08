//! Alternate allocator interface that rounds up requested allocations and resizes to
//! an arbitrary block size and returns the entire available memory instead of only the
//! requested amount

const std = @import("std");
const Allocator = std.mem.Allocator;
pub const AllocError = std.mem.Allocator.Error;
const builtin = @import("builtin");
const mem = std.mem;
const math = std.math;
const assert = std.debug.assert;

const Error = error{OutOfMemory};
const Self = @This();

interface: struct {
    /// type-erased pointer to concrete allocator
    self_opaque: *anyopaque,

    /// Attempt to allocate at minimum `len` bytes aligned to `1 << log2_of_align`.
    ///
    /// `ret_addr` is optionally provided as the first return address of the
    /// allocation call stack. If the value is `0` it means no return address
    /// has been provided.
    alloc: *const fn (self_opaque: *anyopaque, min_len: usize, log2_of_align: u8, ret_addr: usize) ?[]u8,

    /// Attempt to expand or shrink memory in place. `slice.len` must equal the
    /// length requested from the most recent successful call to `alloc` or
    /// `resize`. `log2_of_align` must equal the same value that was passed as the
    /// `log2_of_align` parameter to the original `alloc` call.
    ///
    /// A result of type `usize` indicates the resize was successful and the
    /// allocation now has the same address but a size equal to the returned value.
    ///
    /// A result type of `null` indicates the resize could not be completed without moving the
    /// allocation to a different address.
    ///
    /// `new_min_len` must be greater than zero.
    ///
    /// `ret_addr` is optionally provided as the first return address of the
    /// allocation call stack. If the value is `0` it means no return address
    /// has been provided.
    resize: *const fn (self_opaque: *anyopaque, old_mem: []u8, log2_of_align: u8, new_min_len: usize, ret_addr: usize) ?usize,

    /// Release the memory held by this slice back to the allocator or OS,
    /// invalidating any pointers to its elements.
    ///
    /// `slice.len` must equal the most recent length returned by `alloc` or `resize` call.
    ///
    /// `log2_of_align` must equal the same value that was passed as the
    /// `log2_of_align` parameter to the original `alloc` call.
    ///
    /// `ret_addr` is optionally provided as the first return address of the
    /// allocation call stack. If the value is `0` it means no return address
    /// has been provided.
    free: *const fn (ctx: *anyopaque, old_mem: []u8, log2_of_align: u8, ret_addr: usize) void,
    block_size: *const fn () usize,
},

/// Calls to this function must ensure all inputs are valid, bypasses saftey checks and optimizations
/// at the interface level, though the concrete implementation may provide their own
pub inline fn raw_alloc(self: Self, min_len: usize, log2_of_align: u8, ret_addr: usize) ?[]u8 {
    return self.interface.alloc(self.interface.self_opaque, min_len, log2_of_align, ret_addr);
}

/// Calls to this function must ensure all inputs are valid, bypasses saftey checks and optimizations
/// at the interface level, though the concrete implementation may provide their own
pub inline fn raw_resize(self: Self, old_mem: []u8, log2_of_align: u8, new_min_len: usize, ret_addr: usize) ?usize {
    return self.interface.resize(self.interface.self_opaque, old_mem, log2_of_align, new_min_len, ret_addr);
}

/// Calls to this function must ensure all inputs are valid, bypasses saftey checks and optimizations
/// at the interface level, though the concrete implementation may provide their own
pub inline fn raw_free(self: Self, old_mem: []u8, log2_of_align: u8, ret_addr: usize) void {
    return self.interface.free(self.interface.self_opaque, old_mem, log2_of_align, ret_addr);
}

/// Returns the block size of this block allocator
///
/// (every allocation performed by a BlockAllocator is rounded up to a multiple of this size)
pub fn block_size(self: Self) usize {
    return self.interface.block_size();
}

/// Returns a pointer to undefined memory.
/// Call `destroy` with the result to free the memory.
pub fn create(self: Self, comptime T: type) Error!*T {
    if (@sizeOf(T) == 0) return @as(*T, @ptrFromInt(math.maxInt(usize)));
    const ptr: *T = @ptrCast(try self.alloc_bytes_with_align(@alignOf(T), @sizeOf(T), @returnAddress()));
    return ptr;
}

/// `ptr` should be the return value of `create`, or otherwise
/// have the same address and alignment property.
pub fn destroy(self: Self, ptr: anytype) void {
    const info = @typeInfo(@TypeOf(ptr)).Pointer;
    if (info.size != .One) @compileError("ptr must be a single item pointer");
    const T = info.child;
    if (@sizeOf(T) == 0) return;
    const non_const_ptr = @as([*]u8, @ptrCast(@constCast(ptr)));
    self.raw_free(non_const_ptr[0..@sizeOf(T)], log2(info.alignment), @returnAddress());
}

/// Allocates an array of at least `min_len` items of type `T` and sets all the
/// items to `undefined`. Depending on the Allocator
/// implementation, it may be required to call `free` once the
/// memory is no longer needed, to avoid a resource leak. If the
/// `Allocator` implementation is unknown, then correct code will
/// call `free` when done.
///
/// For allocating a single item, see `create`.
pub fn alloc(self: Self, comptime T: type, min_len: usize) Error![]T {
    return self.alloc_advanced_with_ret_addr(T, null, min_len, @returnAddress());
}

pub fn alloc_with_options(self: Self, comptime T: type, min_len: usize, comptime optional_alignment: ?u29, comptime optional_sentinel: ?T) Error!AllocWithOptionsPayload(T, optional_alignment, optional_sentinel) {
    return self.alloc_with_options_ret_addr(T, min_len, optional_alignment, optional_sentinel, @returnAddress());
}

pub fn alloc_with_options_ret_addr(self: Self, comptime T: type, min_len: usize, comptime optional_alignment: ?u29, comptime optional_sentinel: ?T, return_address: usize) Error!AllocWithOptionsPayload(T, optional_alignment, optional_sentinel) {
    if (optional_sentinel) |sentinel| {
        const slice = try self.alloc_advanced_with_ret_addr(T, optional_alignment, min_len + 1, return_address);
        slice[slice.len - 1] = sentinel;
        return slice[0 .. slice.len - 1 :sentinel];
    } else {
        return self.alloc_advanced_with_ret_addr(T, optional_alignment, min_len, return_address);
    }
}

fn AllocWithOptionsPayload(comptime T: type, comptime alignment: ?u29, comptime sentinel: ?T) type {
    if (sentinel) |s| {
        return [:s]align(alignment orelse @alignOf(T)) T;
    } else {
        return []align(alignment orelse @alignOf(T)) T;
    }
}

/// Allocates an array of at least 'min_len' items of type `T` set to `undefined`
/// followed by 1 more element with value `sentinel`. Depending on the
/// Allocator implementation, it may be required to call `free` once the
/// memory is no longer needed, to avoid a resource leak. If the
/// `Allocator` implementation is unknown, then correct code will
/// call `free` when done.
///
/// For allocating a single item, see `create`.
pub fn alloc_with_sentinel(self: Self, comptime T: type, min_len: usize, comptime sentinel: T) Error![:sentinel]T {
    return self.alloc_with_options_ret_addr(T, min_len, null, sentinel, @returnAddress());
}

pub fn alloc_with_align(self: Self, comptime T: type, comptime alignment: ?u29, min_len: usize) Error![]align(alignment orelse @alignOf(T)) T {
    return self.alloc_advanced_with_ret_addr(T, alignment, min_len, @returnAddress());
}

pub inline fn alloc_advanced_with_ret_addr(self: Self, comptime T: type, comptime alignment: ?u29, min_len: usize, return_address: usize) Error![]align(alignment orelse @alignOf(T)) T {
    const a = alignment orelse @alignOf(T);
    const byte_slice = try self.alloc_with_size_and_align(@sizeOf(T), a, min_len, return_address);
    const type_count = byte_slice.len / @sizeOf(T);
    const type_ptr: [*]align(a) T = @ptrCast(byte_slice.ptr);
    return type_ptr[0..type_count];
}

fn alloc_with_size_and_align(self: Self, comptime type_size: usize, comptime alignment: u29, min_len: usize, return_address: usize) Error![]align(alignment) u8 {
    const byte_count = math.mul(usize, type_size, min_len) catch return Error.OutOfMemory;
    return self.alloc_bytes_with_align(alignment, byte_count, return_address);
}

fn alloc_bytes_with_align(self: Self, comptime alignment: u29, byte_len: usize, return_address: usize) Error![]align(alignment) u8 {
    // The BlockAllocator interface is not intended to solve alignments beyond
    // the minimum OS page size. For these use cases, the caller must use OS
    // APIs directly.
    comptime assert(alignment <= mem.page_size);

    if (byte_len == 0) {
        const ptr = comptime std.mem.alignBackward(usize, math.maxInt(usize), alignment);
        return @as([*]align(alignment) u8, @ptrFromInt(ptr))[0..0];
    }

    const slice = self.raw_alloc(byte_len, log2(alignment), return_address) orelse return Error.OutOfMemory;
    return @as([]align(alignment) u8, @alignCast(slice));
}

/// Requests to modify the size of an allocation, returning the new size of the allocation. It is guaranteed to not move
/// the pointer, however the allocator implementation may refuse the resize
/// request by returning `null`.
pub fn resize(self: Self, old_mem: anytype, new_min_len: usize) ?usize {
    const Slice = @typeInfo(@TypeOf(old_mem)).Pointer;
    const T = Slice.child;
    if (new_min_len == 0) {
        self.free(old_mem);
        return 0;
    }
    if (@sizeOf(T) == 0) {
        return new_min_len;
    }
    if (old_mem.len == 0) {
        return null;
    }
    const old_alloc_slice = type_slice_to_alloc_slice(old_mem);
    const has_sentinel = Slice.sentinel != null;
    const new_type_len = if (has_sentinel) new_min_len + 1 else new_min_len;
    const new_byte_len = math.mul(usize, @sizeOf(T), new_type_len) catch return Error.OutOfMemory;
    const sentinel = if (has_sentinel) old_mem.ptr[old_mem.len] else null;
    if (self.raw_resize(old_alloc_slice, log2(Slice.alignment), new_byte_len, @returnAddress())) |new_real_len| {
        const new_byte_slice: []align(Slice.alignment) u8 = @alignCast(old_alloc_slice.ptr[0..new_real_len]);
        const new_type_slice = byte_slice_as_type_slice(T, new_byte_slice, has_sentinel);
        if (has_sentinel) new_type_slice[new_type_slice.len] = sentinel;
        return new_type_slice.len;
    }
    return null;
}

/// This function requests a new byte size for an existing allocation, which
/// can be larger, smaller, or the same size as the old memory allocation.
/// If `new_min_len` is 0, this is the same as `free` and it always succeeds.
pub fn realloc(self: Self, old_mem: anytype, new_min_len: usize) t: {
    const Slice = @typeInfo(@TypeOf(old_mem)).Pointer;
    break :t Error![]align(Slice.alignment) Slice.child;
} {
    return self.realloc_advanced(old_mem, new_min_len, @returnAddress());
}

pub fn realloc_advanced(self: Self, old_mem: anytype, new_min_len: usize, return_address: usize) t: {
    const Slice = @typeInfo(@TypeOf(old_mem)).Pointer;
    break :t Error![]align(Slice.alignment) Slice.child;
} {
    const Slice = @typeInfo(@TypeOf(old_mem)).Pointer;
    const T = Slice.child;
    if (old_mem.len == 0) {
        return self.alloc_advanced_with_ret_addr(T, Slice.alignment, new_min_len, return_address);
    }
    if (new_min_len == 0) {
        self.free(old_mem);
        const ptr = comptime std.mem.alignBackward(usize, math.maxInt(usize), Slice.alignment);
        return @as([*]align(Slice.alignment) T, @ptrFromInt(ptr))[0..0];
    }

    const old_alloc_slice = type_slice_to_alloc_slice(old_mem);
    const has_sentinel = Slice.sentinel != null;
    const new_type_len = if (has_sentinel) new_min_len + 1 else new_min_len;
    const new_byte_len = math.mul(usize, @sizeOf(T), new_type_len) catch return Error.OutOfMemory;
    const sentinel = if (has_sentinel) old_mem.ptr[old_mem.len] else null;
    if (self.raw_resize(old_alloc_slice, log2(Slice.alignment), new_byte_len, return_address)) |new_real_len| {
        const new_byte_slice: []align(Slice.alignment) u8 = @alignCast(old_alloc_slice.ptr[0..new_real_len]);
        const new_type_slice = byte_slice_as_type_slice(T, new_byte_slice, has_sentinel);
        if (has_sentinel) new_type_slice[new_type_slice.len] = sentinel;
        return new_type_slice;
    }

    const new_mem = self.raw_alloc(new_byte_len, log2(Slice.alignment), return_address) orelse return error.OutOfMemory;
    const copy_len = @min(new_byte_len, old_alloc_slice.len);
    @memcpy(new_mem[0..copy_len], old_alloc_slice[0..copy_len]);
    self.raw_free(old_alloc_slice, log2(Slice.alignment), return_address);

    const new_byte_slice: []align(Slice.alignment) u8 = @alignCast(new_mem);
    const new_type_slice = byte_slice_as_type_slice(T, new_byte_slice, has_sentinel);
    if (has_sentinel) new_type_slice[new_type_slice.len] = sentinel;
    return new_type_slice;
}

/// Free an array allocated with `alloc`. To free a single item,
/// see `destroy`.
pub fn free(self: Self, old_mem: anytype) void {
    const Slice = @typeInfo(@TypeOf(old_mem)).Pointer;
    const old_alloc_slice = type_slice_to_alloc_slice(old_mem);
    if (old_alloc_slice.len == 0) return;
    self.raw_free(old_alloc_slice, log2(Slice.alignment), @returnAddress());
}

inline fn log2(x: u64) u8 {
    assert(x != 0);
    return @as(u8, 63 - @clz(x));
}

fn CopyPtrAttrsWithoutSentinel(
    comptime source: type,
    comptime size: std.builtin.Type.Pointer.Size,
    comptime child: type,
) type {
    const info = @typeInfo(source).Pointer;
    return @Type(.{
        .Pointer = .{
            .size = size,
            .is_const = info.is_const,
            .is_volatile = info.is_volatile,
            .is_allowzero = info.is_allowzero,
            .alignment = info.alignment,
            .address_space = info.address_space,
            .child = child,
            .sentinel = null,
        },
    });
}

fn BytesAsSliceReturnType(comptime T: type, comptime bytesType: type) type {
    return CopyPtrAttrsWithoutSentinel(bytesType, .Slice, T);
}

/// Given a slice of bytes, returns a slice of the specified type
/// backed by those bytes (rounded down to the nearest multiple of @sizeOf(T)), preserving pointer attributes.
fn byte_slice_as_type_slice(comptime T: type, byte_slice: anytype, sentinel: bool) BytesAsSliceReturnType(T, @TypeOf(byte_slice)) {
    if (byte_slice.len == 0) {
        return &[0]T{};
    }
    assert(@sizeOf(T) != 0);

    const cast_target = CopyPtrAttrsWithoutSentinel(@TypeOf(byte_slice), .Many, T);

    const len_without_sentinel = if (sentinel) (byte_slice.len / @sizeOf(T)) - 1 else (byte_slice.len / @sizeOf(T));

    return @as(cast_target, @ptrCast(byte_slice))[0..len_without_sentinel];
}

fn SliceAsBytesReturnType(comptime Slice: type) type {
    return CopyPtrAttrsWithoutSentinel(Slice, .Slice, u8);
}

/// Given a slice, returns a slice of the underlying bytes (not including sentinel), preserving pointer attributes.
fn type_slice_to_alloc_slice(type_slice: anytype) SliceAsBytesReturnType(@TypeOf(type_slice)) {
    const Slice = @TypeOf(type_slice);

    // a slice of zero-bit values always occupies zero bytes
    if (@sizeOf(std.meta.Elem(Slice)) == 0) return &[0]u8{};

    const real_len = get_real_len(type_slice);
    // let's not give an undefined pointer to @ptrCast
    // it may be equal to zero and fail a null check
    if (real_len == 0) return &[0]u8{};

    const cast_target = CopyPtrAttrsWithoutSentinel(Slice, .Many, u8);

    return @as(cast_target, @ptrCast(type_slice))[0 .. real_len * @sizeOf(std.meta.Elem(Slice))];
}

fn get_real_len(type_slice: anytype) usize {
    const Slice = @TypeOf(type_slice);
    return if (std.meta.sentinel(Slice) != null) type_slice.len + 1 else type_slice.len;
}

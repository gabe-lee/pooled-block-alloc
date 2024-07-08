# PooledBlockAlloc
This repo provides `PooledBlockAllocator`, an allocator that uses a backing allocator and spilts its returned allocations
into a pool of memory blocks of user-defined size. It is intended to be a middle-ground between the `GeneralPurposeAllocator`
and the `PageAllocator`, but also come with its own benefits:
- Behavior is largely user-defined. A `PooledBlockAllocator` type is defined by giving a factory function a comptime-known config struct to generate an allocator type tailored to your use case
- Memory is retained and pooled to prevent syscalls for every allocation.
- Memory can be configured to automatically released if certain minimum and maximum thresholds are met, or can also be manually released
- Can be chained in a heirarchy of multiple `PooledBlockAllocators` with different block sizes so that you can choose what parts of your program get what granularity of memory blocks
- Strong asserts of internal state and logic in `Debug` mode
- Configurable assertion and error-handling behavior of user-provided values to public-facing functions
- Configurable error-handling behavior in response to backing allocator failure

## Additional Components (Optional)
### `BlockAllocator`
A generic interface for the conept of a 'BlockAllocator', an allocator that returns the entire span of memory reserved by the backing allocator or OS, as opposed to only the exact amount requested.  
Pros:
- Always get every bit of memory available, reducing the number of times a memory-consumer needs to query its backing allocator whether a resize in-place is possible  

Cons:
- User types will need to implement their own support for the `BlockAllocator` interface
- Getting over-large slices of memory is not always a desired trait

#### Example (using a fictional allocator implementation):
```zig
const needed_bytes: usize = 777;
const alloc_impl = AllocImpl.init(std.heap.page_allocator);

const alloc = alloc_implementation.allocator();
const alloc_slice = try alloc.alloc(needed_bytes);
std.debug.print("alloc_slice.len = {d}", .{alloc_slice.len});
// Output = alloc_slice.len = 777

const b_alloc = alloc_implementation.block_allocator();
const b_alloc_slice = try b_alloc.alloc(needed_bytes);
std.debug.print("b_alloc_slice.len = {d}", .{alloc_slice.len});
// Output = alloc_slice.len = 4096
```
### `StaticAllocBuffer`
A factory function that produces a tightly-coupled 'list' and 'slice' type pair that use a *comptime-defined* pointer to a `BlockAllocator` as part of their type definition (in addition to their element type `T`)

This provides the ergonomic benefits of `ArrayList` without storing a copy of a pointer to the allocator inside every instance;

In addition, since both a 'list' and 'slice' type are generated, one can freely upgrade or downgrade between the two, and consumers of the slice do not need to remember what allocator they need to free themselves with

Pros:
- Greatly improved ergonomics in regards to memory management and safety
- Integration with `BlockAllocator` to reduce the number of calls to allocators for resize

Cons:
- *Slightly* reduced ergonomics when needing to pass a native zig slice to a function. Call the `.slice()` method to automatically reference the correct native zig slice (`[]T`, `[:t]T`, `[]align(a) T`, or `[:t]align(a) T`), or slice manually with `.ptr[start..end]`
- Using the allocator pointer in the type definition creates additional compiled types. For example `StaticAllocBuffer(u8, alloc_1024)` and `StaticAllocBuffer(u8, alloc_256)` produce two separate compiled types

#### Example
```zig
const MediumU32Buf: type = StaticAllocBuffer.define(u32, medium_block_alloc);

fn make_prime_numbers(limit: u32) MediumU32Buf.Slice {
    var list = MediumU32Buf.List.create();
    var i: u32 = 0;
    while (i < limit) {
        if (is_prime(i)) list.append(i);
        i += 1;
    }
    return list.downgrade_into_slice_partial();
}

fn main() !void {
    const primes_under_100 = make_prime_numbers(100);
    defer primes_under_100.release();
    std.debug.print("primes under 100: {}", .{primes_under_100.slice()});
}
```


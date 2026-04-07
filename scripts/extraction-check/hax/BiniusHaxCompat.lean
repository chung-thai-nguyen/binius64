import Hax

open Std.Do
open Std.Tactic
open rust_primitives.sequence

namespace rust_primitives.hax

partial def while_loop_return
    {β : Type}
    {γ : Type}
    (_inv : β → RustM Bool)
    (cond : β → RustM Bool)
    (_termination : β → RustM hax_lib.int.Int)
    (init : β)
    (body : β → RustM
      (core_models.ops.control_flow.ControlFlow
        (core_models.ops.control_flow.ControlFlow
          γ
          (rust_primitives.hax.Tuple2 rust_primitives.hax.Tuple0 β))
        β)) :
    RustM (core_models.ops.control_flow.ControlFlow γ β) := do
  if ← cond init then
    match ← body init with
    | core_models.ops.control_flow.ControlFlow.Break
      (core_models.ops.control_flow.ControlFlow.Break ret) =>
        pure (core_models.ops.control_flow.ControlFlow.Break ret)
    | core_models.ops.control_flow.ControlFlow.Break
      (core_models.ops.control_flow.ControlFlow.Continue ret) =>
        pure (core_models.ops.control_flow.ControlFlow.Continue ret._1)
    | core_models.ops.control_flow.ControlFlow.Continue next =>
        while_loop_return _inv cond _termination next body
  else
    pure (core_models.ops.control_flow.ControlFlow.Continue init)

end rust_primitives.hax

namespace alloc.vec

@[spec]
def from_elem (α : Type) (x : α) (n : usize) :
    RustM (alloc.vec.Vec α alloc.alloc.Global) := do
  pure ⟨Array.replicate n.toNat x, by simpa using USize64.toNat_lt_size n⟩

end alloc.vec

namespace alloc.vec.Impl

@[spec]
def with_capacity (α : Type) (_n : usize) :
    RustM (alloc.vec.Vec α alloc.alloc.Global) := do
  alloc.vec.Impl.new α ⟨⟩

end alloc.vec.Impl

namespace alloc.vec.Impl_1

@[spec]
def push (α : Type) (_alloc : Type) (xs : alloc.vec.Vec α alloc.alloc.Global) (x : α) :
    RustM (alloc.vec.Vec α alloc.alloc.Global) := do
  if h : xs.val.size + 1 < USize64.size then
    pure ⟨xs.val.push x, by simpa [Array.size_push] using h⟩
  else
    .fail .maximumSizeExceeded

@[spec]
def as_slice {α : Type} (xs : alloc.vec.Vec α alloc.alloc.Global) :
    RustM (RustSlice α) := do
  pure xs

@[spec]
def is_empty (α : Type) (_alloc : Type) (xs : alloc.vec.Vec α alloc.alloc.Global) :
    RustM Bool := do
  pure (xs.val.size == 0)

end alloc.vec.Impl_1

namespace alloc.slice.Impl

@[spec]
def into_vec (α : Type) (_alloc : Type) (xs : RustSlice α) :
    RustM (alloc.vec.Vec α alloc.alloc.Global) := do
  pure xs

end alloc.slice.Impl

namespace core_models.slice.Impl

@[spec]
def first (T : Type) (s : RustSlice T) : RustM T := do
  rust_primitives.sequence.seq_first T s

@[spec]
def last (T : Type) (s : RustSlice T) : RustM T := do
  let len ← rust_primitives.sequence.seq_len T s
  if len == 0 then
    .fail .arrayOutOfBounds
  else
    s[(len - (1 : usize))]_?

end core_models.slice.Impl

namespace core_models.cmp.PartialEq

@[spec]
def ne
    (Self : Type)
    (Rhs : Type)
    [core_models.cmp.PartialEq.AssociatedTypes Self Rhs]
    [core_models.cmp.PartialEq Self Rhs]
    (x : Self)
    (y : Rhs) :
    RustM Bool := do
  ((← core_models.cmp.PartialEq.eq Self Rhs x y) ==? false)

end core_models.cmp.PartialEq

namespace core_models.iter.traits.iterator.Iterator

@[spec]
def map
    (Self : Type)
    (O : Type)
    (F : Type)
    [core_models.iter.traits.iterator.Iterator.AssociatedTypes Self]
    [core_models.iter.traits.iterator.Iterator Self]
    [core_models.ops.function.FnOnce.AssociatedTypes F
      (core_models.iter.traits.iterator.Iterator.Item Self)]
    [core_models.ops.function.FnOnce
      F
      (core_models.iter.traits.iterator.Iterator.Item Self)
      (associatedTypes := {
        show
          core_models.ops.function.FnOnce.AssociatedTypes
            F
            (core_models.iter.traits.iterator.Iterator.Item Self)
        by infer_instance
        with Output := O
      })]
    (self : Self)
    (f : F) :
    RustM (core_models.iter.adapters.map.Map Self F) := do
  core_models.iter.adapters.map.Impl.new Self F self f

partial def fold
    {Self : Type}
    [core_models.iter.traits.iterator.Iterator.AssociatedTypes Self]
    [hAssoc :
      core_models.iter.traits.iterator.Iterator.AssociatedTypes Self]
    [core_models.iter.traits.iterator.Iterator Self]
    {B : Type}
    {F : Type}
    [core_models.ops.function.FnOnce.AssociatedTypes F
      (rust_primitives.hax.Tuple2 B (core_models.iter.traits.iterator.Iterator.Item Self))]
    [hFn :
      core_models.ops.function.FnOnce
        F
        (rust_primitives.hax.Tuple2 B (core_models.iter.traits.iterator.Iterator.Item Self))
        (associatedTypes := {
          show
            core_models.ops.function.FnOnce.AssociatedTypes
              F
              (rust_primitives.hax.Tuple2 B (core_models.iter.traits.iterator.Iterator.Item Self))
          by infer_instance
          with Output := B
        })]
    (self : Self)
    (init : B)
    (f : F) :
    RustM B := do
  let ⟨self, next?⟩ ← core_models.iter.traits.iterator.Iterator.next Self self
  match next? with
  | core_models.option.Option.None => pure init
  | core_models.option.Option.Some item =>
      let acc ←
        core_models.ops.function.FnOnce.call_once
          F
          (rust_primitives.hax.Tuple2 B (core_models.iter.traits.iterator.Iterator.Item Self))
          f
          (rust_primitives.hax.Tuple2.mk init item)
      fold self acc f

@[spec]
def collect
    (Self : Type)
    (_B : Type)
    [core_models.iter.traits.iterator.Iterator.AssociatedTypes Self]
    [core_models.iter.traits.iterator.Iterator Self]
    (self : Self) :
    RustM
      (alloc.vec.Vec
        (core_models.iter.traits.iterator.Iterator.Item Self)
        alloc.alloc.Global) := do
  let mut out ← alloc.vec.Impl.new _ ⟨⟩
  let mut it := self
  let mut done := false
  while !done do
    let ⟨nextIt, next?⟩ ← core_models.iter.traits.iterator.Iterator.next Self it
    it := nextIt
    match next? with
    | core_models.option.Option.None =>
        done := true
    | core_models.option.Option.Some x =>
        out ← alloc.vec.Impl_1.push _ alloc.alloc.Global out x
  pure out

end core_models.iter.traits.iterator.Iterator

namespace core_models.iter.traits.collect

@[reducible] instance implRustSliceIntoIterAssociatedTypes (T : Type) :
    IntoIterator.AssociatedTypes (RustSlice T) where
  IntoIter := core_models.slice.iter.Iter T

instance implRustSliceIntoIter (T : Type) :
    IntoIterator (RustSlice T) where
  into_iter := fun s => core_models.slice.Impl.iter T s

@[reducible] instance implVecIntoIterAssociatedTypes (T : Type) :
    IntoIterator.AssociatedTypes (alloc.vec.Vec T alloc.alloc.Global) where
  IntoIter := core_models.slice.iter.Iter T

instance implVecIntoIter (T : Type) :
    IntoIterator (alloc.vec.Vec T alloc.alloc.Global) where
  into_iter := fun s => core_models.slice.Impl.iter T s

end core_models.iter.traits.collect

namespace core_models.slice

@[reducible] instance implSliceIndexUsizeAssoc (T : Type) :
    SliceIndex.AssociatedTypes usize (RustSlice T) where
  Output := T

instance implSliceIndexUsize (T : Type) :
    SliceIndex usize (RustSlice T) where
  get := fun i s => do
    if h : i.toNat < s.val.size then
      pure (core_models.option.Option.Some s.val[i.toNat])
    else
      pure core_models.option.Option.None

@[reducible] instance implSliceIndexRangeFromAssoc (T : Type) :
    SliceIndex.AssociatedTypes (core_models.ops.range.RangeFrom usize) (RustSlice T) where
  Output := RustSlice T

instance implSliceIndexRangeFrom (T : Type) :
    SliceIndex (core_models.ops.range.RangeFrom usize) (RustSlice T) where
  get := fun r s => do
    if r.start.toNat <= s.val.size then
      let out ← rust_primitives.slice.slice_slice T s r.start (USize64.ofNat s.val.size)
      pure (core_models.option.Option.Some out)
    else
      pure core_models.option.Option.None

@[reducible] instance implSliceIndexRangeAssoc (T : Type) :
    SliceIndex.AssociatedTypes (core_models.ops.range.Range usize) (RustSlice T) where
  Output := RustSlice T

instance implSliceIndexRange (T : Type) :
    SliceIndex (core_models.ops.range.Range usize) (RustSlice T) where
  get := fun r s => do
    if r.start.toNat <= r._end.toNat ∧ r._end.toNat <= s.val.size then
      let out ← rust_primitives.slice.slice_slice T s r.start r._end
      pure (core_models.option.Option.Some out)
    else
      pure core_models.option.Option.None

@[reducible] instance implSliceIndexRangeToAssoc (T : Type) :
    SliceIndex.AssociatedTypes (core_models.ops.range.RangeTo usize) (RustSlice T) where
  Output := RustSlice T

instance implSliceIndexRangeTo (T : Type) :
    SliceIndex (core_models.ops.range.RangeTo usize) (RustSlice T) where
  get := fun r s => do
    if r._end.toNat <= s.val.size then
      let out ← rust_primitives.slice.slice_slice T s (0 : usize) r._end
      pure (core_models.option.Option.Some out)
    else
      pure core_models.option.Option.None

end core_models.slice

instance instSeqBEq (α : Type) [BEq α] :
    BEq (rust_primitives.sequence.Seq α) where
  beq x y := x.val == y.val

instance instRustArrayBEq (α : Type) [BEq α] (n : usize) :
    BEq (RustArray α n) where
  beq x y := x.toVec.toArray == y.toVec.toArray

instance (priority := low) instCoreModelsPartialEqAssocOfBEq (α : Type) [BEq α] :
    core_models.cmp.PartialEq.AssociatedTypes α α where

instance (priority := low) instCoreModelsPartialEqOfBEq (α : Type) [BEq α] :
    core_models.cmp.PartialEq α α where
  eq := fun x y => pure (x == y)

@[reducible] instance instVecSlicePartialEqAssoc (α : Type) [BEq α] :
    core_models.cmp.PartialEq.AssociatedTypes
      (alloc.vec.Vec α alloc.alloc.Global)
      (RustSlice α) where

instance instVecSlicePartialEq (α : Type) [BEq α] :
    core_models.cmp.PartialEq
      (alloc.vec.Vec α alloc.alloc.Global)
      (RustSlice α) where
  eq := fun x y => pure (x == y)

instance instGetElemResultRangeFromSeq (α : Type) :
    GetElemResult
      (RustSlice α)
      (core_models.ops.range.RangeFrom usize)
      (RustSlice α) where
  getElemResult xs r := do
    rust_primitives.slice.slice_slice α xs r.start (USize64.ofNat xs.val.size)

instance instGetElemResultRangeToSeq (α : Type) :
    GetElemResult
      (RustSlice α)
      (core_models.ops.range.RangeTo usize)
      (RustSlice α) where
  getElemResult xs r := do
    rust_primitives.slice.slice_slice α xs (0 : usize) r._end

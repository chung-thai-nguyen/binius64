import Hax

open Std.Do
open Std.Tactic

abbrev binius_field.ghash.BinaryField128bGhash := u128

namespace binius_field.ghash.Impl

@[spec]
def new (x : u128) : RustM binius_field.ghash.BinaryField128bGhash := pure x

@[spec]
def val (x : binius_field.ghash.BinaryField128bGhash) : RustM u128 := pure x

end binius_field.ghash.Impl

namespace binius_field.field

class Field (F : Type) where
  ZERO : F
  ONE : F

instance : Field binius_field.ghash.BinaryField128bGhash where
  ZERO := 0
  ONE := 1

end binius_field.field

namespace binius_field.ghash

@[reducible] instance instPartialEqAssoc :
    core_models.cmp.PartialEq.AssociatedTypes
      BinaryField128bGhash
      BinaryField128bGhash where

instance instPartialEq :
    core_models.cmp.PartialEq
      BinaryField128bGhash
      BinaryField128bGhash where
  eq := fun x y => pure (x == y)

@[reducible] instance instAddAssoc :
    core_models.ops.arith.Add.AssociatedTypes
      BinaryField128bGhash
      BinaryField128bGhash where
  Output := BinaryField128bGhash

instance instAdd :
    core_models.ops.arith.Add
      BinaryField128bGhash
      BinaryField128bGhash where
  add := fun x y => pure (x + y)

@[reducible] instance instSubAssoc :
    core_models.ops.arith.Sub.AssociatedTypes
      BinaryField128bGhash
      BinaryField128bGhash where
  Output := BinaryField128bGhash

instance instSub :
    core_models.ops.arith.Sub
      BinaryField128bGhash
      BinaryField128bGhash where
  sub := fun x y => pure (x - y)

@[reducible] instance instMulAssoc :
    core_models.ops.arith.Mul.AssociatedTypes
      BinaryField128bGhash
      BinaryField128bGhash where
  Output := BinaryField128bGhash

instance instMul :
    core_models.ops.arith.Mul
      BinaryField128bGhash
      BinaryField128bGhash where
  mul := fun x y => pure (x * y)

instance instAddAssignAssoc :
    core_models.ops.arith.AddAssign.AssociatedTypes
      BinaryField128bGhash
      BinaryField128bGhash where

instance instAddAssign :
    core_models.ops.arith.AddAssign
      BinaryField128bGhash
      BinaryField128bGhash where
  add_assign := fun x y => pure (x + y)

instance instSubAssignAssoc :
    core_models.ops.arith.SubAssign.AssociatedTypes
      BinaryField128bGhash
      BinaryField128bGhash where

instance instSubAssign :
    core_models.ops.arith.SubAssign
      BinaryField128bGhash
      BinaryField128bGhash where
  sub_assign := fun x y => pure (x - y)

instance instMulAssignAssoc :
    core_models.ops.arith.MulAssign.AssociatedTypes
      BinaryField128bGhash
      BinaryField128bGhash where

instance instMulAssign :
    core_models.ops.arith.MulAssign
      BinaryField128bGhash
      BinaryField128bGhash where
  mul_assign := fun x y => pure (x * y)

end binius_field.ghash

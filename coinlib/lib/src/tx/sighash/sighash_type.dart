/// Encapsulates the signature hash type to be used for an input signature.
/// Signatures may sign different output and inputs to allow for transaction
/// modifications. To sign an entire transaction the [all] constructor should be
/// used.
/// /// Supports SIGHASH_ANYPREVOUT and SIGHASH_ANYPREVOUTANYSCRIPT.
class SigHashType {
  /// Special value representing the default Schnorr behavior to sign everything.
  /// This is encoded as an absent byte.
  static const schnorrDefaultValue = 0;

  /// Value to sign all outputs
  static const allValue = 1;

  /// Value to sign no outputs
  static const noneValue = 2;

  /// Value to sign the output at the same index as the input
  static const singleValue = 3;

  /// Flag that can be combined with other hash type values to sign only the input containing the signature
  static const anyOneCanPayFlag = 0x80;

  /// Flag for SIGHASH_ANYPREVOUT (APO)
  static const anyPrevOutFlag = 0x40;

  /// Flag for SIGHASH_ANYPREVOUTANYSCRIPT (APOAS)
  static const anyPrevOutAnyScriptFlag = 0xC0;

  /// Mask to extract the base hash type (bits 0-5)
  static const baseMask = 0x3F;

  /// The single-byte representation of the sighash type.
  final int value;

  /// Private constructor to create an instance with a specific value.
  const SigHashType._(this.value);

  /// Factory constructors for base types
  static SigHashType get schnorrDefault =>
      const SigHashType._(schnorrDefaultValue);

  static SigHashType get all => const SigHashType._(allValue);

  static SigHashType get none => const SigHashType._(noneValue);

  static SigHashType get single => const SigHashType._(singleValue);

  /// Method to add ANYONECANPAY flag
  SigHashType get anyOneCanPay {
    _checkInvalidCombination(anyOneCanPayFlag);
    return SigHashType._(value | anyOneCanPayFlag);
  }

  /// Method to add ANYPREVOUT flag
  SigHashType get anyPrevOut {
    _checkInvalidCombination(anyPrevOutFlag);
    return SigHashType._(value | anyPrevOutFlag);
  }

  /// Method to add ANYPREVOUTANYSCRIPT flag
  SigHashType get anyPrevOutAnyScript {
    _checkInvalidCombination(anyPrevOutAnyScriptFlag);
    return SigHashType._(value | anyPrevOutAnyScriptFlag);
  }

  /// Extracts the base type (ALL, NONE, SINGLE, or DEFAULT).
  int get baseType => value & baseMask;

  /// If this is the default hash type for a Schnorr signature.
  bool get isSchnorrDefault => value == schnorrDefaultValue;

  /// All outputs shall be signed.
  bool get isAll => baseType == allValue || isSchnorrDefault;

  /// No outputs shall be signed.
  bool get isNone => baseType == noneValue;

  /// Only the output with the same index as the input shall be signed.
  bool get isSingle => baseType == singleValue;

  /// The signature only signs the input containing it.
  bool get isAnyOneCanPay => (value & anyOneCanPayFlag) != 0;

  /// The signature can sign any previous output.
  bool get isAnyPrevOut =>
      (value & (anyPrevOutFlag | anyPrevOutAnyScriptFlag)) == anyPrevOutFlag;

  /// The signature can sign any previous output and any script.
  bool get isAnyPrevOutAnyScript =>
      (value & (anyPrevOutFlag | anyPrevOutAnyScriptFlag)) ==
      anyPrevOutAnyScriptFlag;

  /// Validates if the given value represents a valid SigHashType.
  static bool validValue(int value) {
    // Extract base type
    final baseType = value & baseMask;

    // Validate base type
    if (baseType != schnorrDefaultValue &&
        baseType != allValue &&
        baseType != noneValue &&
        baseType != singleValue) {
      return false;
    }

    // Extract flags
    final hasAnyOneCanPay = (value & anyOneCanPayFlag) != 0;
    final hasAnyPrevOut = (value & anyPrevOutFlag) != 0;
    final hasAnyPrevOutAnyScript =
        (value & anyPrevOutAnyScriptFlag) == anyPrevOutAnyScriptFlag;

    // Check for invalid flag combinations
    final totalFlagsSet = [
      hasAnyOneCanPay,
      hasAnyPrevOut,
      hasAnyPrevOutAnyScript,
    ].where((flag) => flag).length;

    if (totalFlagsSet > 1) {
      // Cannot combine ANYONECANPAY with ANYPREVOUT or ANYPREVOUTANYSCRIPT
      // Cannot combine ANYPREVOUT with ANYPREVOUTANYSCRIPT
      return false;
    }

    // If all checks pass, the value is valid
    return true;
  }

  /// Creates a SigHashType from an integer value after validating it.
  factory SigHashType.fromValue(int value) {
    if (!validValue(value)) {
      throw ArgumentError.value(value, 'value', 'Not a valid sighash type');
    }
    return SigHashType._(value);
  }

  /// Checks for invalid flag combinations when adding a new flag.
  void _checkInvalidCombination(int newFlag) {
    // Check if the new flag is already set
    if ((value & newFlag) != 0) {
      throw StateError('Flag is already set');
    }

    // Check for invalid combinations
    final isInvalidCombination =
        // Cannot combine ANYONECANPAY with ANYPREVOUT or ANYPREVOUTANYSCRIPT
        (newFlag == anyOneCanPayFlag &&
                (isAnyPrevOut || isAnyPrevOutAnyScript)) ||
            (isAnyOneCanPay &&
                (newFlag == anyPrevOutFlag ||
                    newFlag == anyPrevOutAnyScriptFlag)) ||
            // Cannot combine ANYPREVOUT with ANYPREVOUTANYSCRIPT
            (newFlag == anyPrevOutFlag && isAnyPrevOutAnyScript) ||
            (isAnyPrevOut && newFlag == anyPrevOutAnyScriptFlag);

    if (isInvalidCombination) {
      throw StateError('Invalid flag combination');
    }
  }

  @override
  bool operator ==(Object other) =>
      other is SigHashType && value == other.value;

  @override
  int get hashCode => value;
}

void main() {
  final sighashType = SigHashType.all.anyPrevOut;

  print(
    'Value: 0x${sighashType.value.toRadixString(16)}',
  ); // Prints: Value: 0xc1

  // Accessing properties
  print('isAll: ${sighashType.isAll}'); // true
  print('isAnyOneCanPay: ${sighashType.isAnyOneCanPay}'); // false
  print('isAnyPrevOut: ${sighashType.isAnyPrevOut}'); // false
  print('isAnyPrevOutAnyScript: ${sighashType.isAnyPrevOutAnyScript}'); // true
}

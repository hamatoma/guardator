import 'dart:io';

import 'cipher.dart';
import 'string_tools.dart';

class DataSafeIO extends DataSafe {
  DataSafeIO(
    super.data,
    super.cipher, {
    super.indexMask1 = 0,
    super.indexMask2 = 1,
  });

  /// Reads a data safe from a file named [filename].
  ///
  /// [cipher] is used to encrypt the stored secrets.
  /// [indexMask1] and [indexMask1] are indexes of two random bytes
  /// used to hide the length information.
  DataSafeIO.fromFile(
    String filename,
    Cipher cipher, {
    int indexMask1 = 0,
    int indexMask2 = 1,
  }) : super(
          File(filename).readAsBytesSync(),
          cipher,
          indexMask1: indexMask1,
          indexMask2: indexMask2,
        );

  DataSafeIO.fromLength(
    super.length,
    super.cipher, {
    super.indexMask1,
    super.indexMask2 = 0,
  }) : super.fromLength();

  /// Writes the data safe into a file named [filename].
  ///
  /// Returns true on success.
  bool write(String filename) {
    var rc = true;
    final output = File(filename);
    try {
      output.writeAsBytesSync(data);
      log("written: $output");
    } on Exception catch (exc) {
      error('$exc');
      rc = false;
    }
    return rc;
  }
}

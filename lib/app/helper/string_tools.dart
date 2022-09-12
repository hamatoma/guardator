import 'dart:io';

bool log(String message) {
  stdout.write('$message\n');
  return true;
}

bool error(String message) {
  stderr.write('+++ $message\n');
  return false;
}

/// Converts a [text] into an integer.
///
/// [text] may be decimal or hexadecimal (prefix '0x')
int? stringToInt(String text) {
  var radix = 10;
  var text2 = text;
  if (text.startsWith('0x') || text.startsWith('0X')) {
    radix = 16;
    text2 = text.substring(2);
  }
  final rc = int.tryParse(text2, radix: radix);
  return rc;
}

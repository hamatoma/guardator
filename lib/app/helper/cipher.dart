import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:encrypt/encrypt.dart' as m_encrypt;
import 'package:sprintf/sprintf.dart';

import 'string_tools.dart';

//F/^}/
/// Converts [data] (a list of codepoints) into a string.
///
/// If [masks] != null data is encoded with this xor [masks].
String fromCodepoints({required List<int> data, List<int>? masks}) {
  String rc;
  if (masks == null) {
    rc = String.fromCharCodes(data);
  } else {
    final data2 = <int>[];
    var ix = 0;
    var ixMasks = 0;
    while (ix < data.length) {
      if (ixMasks >= masks.length) {
        ixMasks = 0;
      }
      data2.add(data[ix++] ^ masks[ixMasks++]);
    }
    rc = String.fromCharCodes(data2);
  }
  return rc;
}

//F/^}/
class ByteCounter {
  final int codepoint;
  int count = 0;
  ByteCounter(this.codepoint);
}

//F/^}/
/// Ciphers/deciphers data.
class Cipher {
  //M1
  static const defaultRandom1 = 1.7829273E22;
  //M1
  static const defaultRandom2 = 3.3829391E-32;
  //M1
  static const defaultVersion = 3;
  //M1
  static const _secret32 = 'fdla=au749023jg-y02umHPE#l?89_ab';
  //M1
  static const _secret16 = 'u749023jg-y02umH';
  //M1
  static double random1 = defaultRandom1;
  //M1
  static double random2 = defaultRandom2;
  //M1
  static double random3 = defaultRandom2;
  //M1
  static const notHex =
      'QWERTZUIOPASDFGHJKLYXCVBNM.,:;^456327810!~+%&/()=?oplyxcvbnm-_';
  //M1
  static const nibbleToChar = [
    'q',
    'w',
    'e',
    'r',
    't',
    'z',
    'u',
    'i',
    'a',
    's',
    'd',
    'f',
    'g',
    'h',
    'j',
    'k'
  ];
  //M1
  static const charToNibble = {
    'q': 0,
    'w': 1,
    'e': 2,
    'r': 3,
    't': 4,
    'z': 5,
    'u': 6,
    'i': 7,
    'a': 8,
    's': 9,
    'd': 10,
    'f': 11,
    'g': 12,
    'h': 13,
    'j': 14,
    'k': 15
  };
  //M1
  int _defaultSalt = 3;
  //M1
  int version;
  //M1
  String _encryptionSecret = '';

  //M10
  Cipher({String secret = '1989111220041991', this.version = defaultVersion}) {
    _encryptionSecret = secret;
    _defaultSalt = _encryptionSecret.hashCode;
  }
  //M10
  int get defaultSalt => _defaultSalt;
  //M10
  String get secret => _encryptionSecret;

  //M10
  m_encrypt.IV buildIV(int salt) {
    var salt2 = salt;
    final buffer = StringBuffer();
    while (salt2 != 0) {
      buffer.writeCharCode('A'.codeUnits[0] + salt2 % 4);
      salt2 ~/= 4;
    }
    buffer.write('jkFDA82lx92u92.,27.s.9+'.substring(0, 16 - buffer.length));
    return m_encrypt.IV.fromUtf8(buffer.toString());
  }

  //M10
  /// Converts a [text] into a specially coded hex string.
  String bytesToHex(Uint8List bytes) {
    final rc = StringBuffer();
    for (final byte in bytes) {
      rc.write(nibbleToChar[byte ~/ 16]);
      rc.write(nibbleToChar[byte % 16]);
    }
    return rc.toString();
  }

  //M10
  String cipher(String text) {
    String rc;
    final salt = DateTime.now().microsecond;
    switch (version) {
      case 3:
        rc = encodeV3(text: text, salt: salt, secret: _encryptionSecret);
        break;
      case 2:
        rc = encodeV2(text: text, salt: salt, secret: _encryptionSecret);
        break;
      default:
        rc =
            encodeV1(text: text, salt: _defaultSalt, secret: _encryptionSecret);
        break;
    }
    return rc;
  }

  //M10
  /// Returns the cleaned [text]: all not special hex characters are removed.
  String cleanHex(String text) {
    String rc = '';
    for (int ix = 0; ix < text.length; ix++) {
      final char = text[ix];
      if (charToNibble.containsKey(char)) {
        rc += char;
      }
    }
    return rc;
  }

  //M10
  /// Encrypts/decrypts [data] with given [secret] and [salt].
  ///
  /// Note: AES is symetric: Encoding/decoding is the same algorithm.
  Uint8List convertRawAES({
    required Uint8List data,
    required bool encrypt,
    required Uint8List secret,
    Uint8List? salt,
  }) {
    final iv = salt == null ? m_encrypt.IV.fromLength(16) : m_encrypt.IV(salt);
    final encrypter = m_encrypt.Encrypter(m_encrypt.AES(m_encrypt.Key(secret)));
    Uint8List rc;
    if (encrypt) {
      final data2 = encrypter.encryptBytes(data, iv: iv);
      rc = data2.bytes;
    } else {
      final data2 = encrypter.decryptBytes(m_encrypt.Encrypted(data), iv: iv);
      rc = Uint8List.fromList(data2);
    }
    return rc;
  }

  //M10
  String? decipher(String encodedText) {
    String? rc;
    switch (version) {
      case 3:
        rc = decodeV3(encoded: encodedText, secret: _encryptionSecret);
        break;
      case 2:
        rc = decodeV2(encoded: encodedText, secret: _encryptionSecret);
        break;
      default:
        rc = decodeV1(encoded: encodedText, secret: _encryptionSecret);
        break;
    }
    return rc;
  }

  //M10
  String? decodeAES({
    required Uint8List data,
    required String secret,
    String? salt,
  }) {
    String? rc;
    final secret2 = stringToBytes(
      secret,
      size: 32,
      defaultAdditions: _secret32,
    );
    final salt2 = stringToBytes(
      salt,
      size: 16,
      defaultAdditions: _secret16,
    );
    final rc2 = convertRawAES(
      data: data,
      encrypt: false,
      secret: secret2!,
      salt: salt2 == null ? null : Uint8List.fromList(salt2),
    );
    try {
      rc = utf8.decode(rc2);
    } on FormatException {
      rc = null;
    }
    return rc;
  }

  //M10
  /// Decodes the [encoded] text with [salt] and [secret] (algorithm 1).
  String? decodeV1({required String encoded, String secret = ''}) {
    final bytes = hexToBytes(encoded);
    for (var ix = 0; ix < bytes.length; ix++) {
      bytes[ix] = (bytes[ix] + 256 - defaultSalt % 255) % 256;
    }
    String? rc;
    try {
      rc = utf8.decode(bytes);
    } on FormatException {
      rc = null;
    }
    return rc;
  }

  //M10
  /// Decodes the [encoded] text with [salt] and [secret] (algorithm 2).
  String? decodeV2({required String encoded, String secret = ''}) {
    var secret2 = secret;
    final cleanEncoded = cleanHex(encoded);
    if (cleanEncoded.length < 4) {
      throw ArgumentError('encoded too short: $encoded');
    }
    final saltPart = hexToBytes(cleanEncoded.substring(0, 4));
    final salt = saltPart[0] * 256 + saltPart[1];
    final textBytes = hexToBytes(cleanEncoded.substring(4));
    if (secret2.length < 16) {
      secret2 += 'rtlprmpftiowaoaj'.substring(0, 16 - secret.length);
    }
    final secretBytes = utf8.encode(secret2);
    for (var ix = 0; ix < textBytes.length; ix++) {
      textBytes[ix] = (512 +
              textBytes[ix] -
              secretBytes[ix % secretBytes.length] -
              salt % 256) %
          256;
    }
    String? rc;
    try {
      rc = utf8.decode(textBytes);
    } on FormatException {
      rc = null;
    }
    return rc;
  }

  //M10
  /// Decodes the [encoded] text with [salt] and [secret] (algorithm 3).
  String? decodeV3({required String encoded, String secret = ''}) {
    var secret2 = secret;
    final cleanEncoded = cleanHex(encoded);
    if (cleanEncoded.length < 4) {
      throw ArgumentError('encoded too short: $encoded');
    }
    final saltPart = hexToBytes(cleanEncoded.substring(0, 4));
    final salt = saltPart[0] * 256 + saltPart[1];
    final textBytes = hexToBytes(cleanEncoded.substring(4));
    if (secret2.length < 32) {
      secret2 +=
          'rtlprmpftiowaoajJuppyId07329927('.substring(0, 32 - secret2.length);
    } else {
      secret2 = secret.substring(0, 32);
    }
    // for (var ix = 0; ix < textBytes.length; ix++) {
    //   textBytes[ix] = (256 + textBytes[ix] - salt % 256) % 256;
    // }
    final iv = buildIV(salt);
    final encrypter =
        m_encrypt.Encrypter(m_encrypt.AES(m_encrypt.Key.fromUtf8(secret2)));
    final encrypted = m_encrypt.Encrypted(textBytes);
    String? rc;
    try {
      rc = encrypter.decrypt(encrypted, iv: iv);
    } on FormatException {
      rc = null;
    } on ArgumentError {
      rc = null;
    }
    return rc;
  }

  //M10
  Uint8List encodeAES({
    required String data,
    required String secret,
    String? salt,
  }) {
    final secret2 = stringToBytes(
      secret,
      size: 32,
      defaultAdditions: _secret32,
    );
    final salt2 = stringToBytes(
      salt,
      size: 16,
      defaultAdditions: _secret16,
    );
    final rc = convertRawAES(
      data: Uint8List.fromList(utf8.encode(data)),
      encrypt: true,
      secret: secret2!,
      salt: salt2,
    );
    return rc;
  }

  //M10
  /// Encodes the [text] with [salt] and [secret] (algorithm 1).
  String encodeV1({required String text, int salt = 3, String secret = ''}) {
    final textBytes = Uint8List.fromList(utf8.encode(text));
    for (var ix = 0; ix < textBytes.length; ix++) {
      textBytes[ix] = (textBytes[ix] + salt % 255) % 256;
    }
    final rc = bytesToHex(textBytes);
    return rc;
  }

  //M10
  /// Encodes the [text] with [salt] and [secret] (algorithm 2).
  String encodeV2({required String text, int salt = 0, String secret = ''}) {
    final salt2 = salt & 0xffff;
    var secret2 = secret;
    final textBytes = Uint8List.fromList(utf8.encode(text));
    if (secret2.length < 16) {
      secret2 += 'rtlprmpftiowaoaj'.substring(0, 16 - secret2.length);
    }
    final secretBytes = utf8.encode(secret2);
    for (var ix = 0; ix < textBytes.length; ix++) {
      textBytes[ix] =
          (textBytes[ix] + secretBytes[ix % secretBytes.length] + salt2 % 256) %
              256;
    }
    final rc = bytesToHex(Uint8List.fromList([salt2 ~/ 256, salt2 % 256])) +
        bytesToHex(textBytes);
    return rc;
  }

  //M10
  /// Encodes the [text] with [salt] and [secret] (algorithm 3).
  String encodeV3({required String text, int salt = 0, String secret = ''}) {
    final salt2 = salt & 0xffff;
    var secret2 = secret;
    final textBytes = Uint8List.fromList(utf8.encode(text));
    if (secret2.length < 32) {
      secret2 +=
          'rtlprmpftiowaoajJuppyId07329927('.substring(0, 32 - secret2.length);
    } else {
      secret2 = secret.substring(0, 32);
    }
    final iv = buildIV(salt);
    final encrypter =
        m_encrypt.Encrypter(m_encrypt.AES(m_encrypt.Key.fromUtf8(secret2)));
    final encrypted = encrypter.encryptBytes(textBytes, iv: iv);
    final rc = bytesToHex(Uint8List.fromList([salt2 ~/ 256, salt2 % 256])) +
        bytesToHex(encrypted.bytes);
    return rc;
  }

  //M10
  /// Adds irrelevant characters to [text] to "hide" the true information.
  ///
  /// [salt] randomizes the number of additional characters.
  String extendHex(String text, int salt) {
    final rc = StringBuffer(notHex[salt % notHex.length]);
    rc.write(notHex[salt ~/ 2 % notHex.length]);
    final random1 = salt * 7;
    final distance1 = 1 + (salt % 7);
    final distance2 = 1 + (salt % 3);
    for (int ix = 0; ix < text.length; ix++) {
      rc.write(text[ix]);
      if (ix % distance1 == 0) {
        rc.write(notHex[(random1 + ix) % notHex.length]);
      }
      if (ix % distance2 == 0) {
        rc.write(notHex[(salt + ix) % notHex.length]);
      }
    }
    return rc.toString();
  }

  //M10
  /// Converts a special coded hex string named [text] into a list of bytes.
  Uint8List hexToBytes(String text) {
    final rc = <int>[];
    if (text.length % 2 != 0) {
      throw ArgumentError(
        'invalid coded string length (${text.length}): $text',
      );
    }
    for (int ix = 0; ix < text.length; ix += 2) {
      var char = text[ix];
      if (!charToNibble.containsKey(char)) {
        throw ArgumentError('invalid hex: $char');
      }
      var byte = charToNibble[char]! * 16;
      char = text[ix + 1];
      if (!charToNibble.containsKey(char)) {
        throw ArgumentError('invalid code: $char');
      }
      byte += charToNibble[char]!;
      rc.add(byte);
    }
    return Uint8List.fromList(rc);
  }

  //M10
  /// Sets the encryption secret.
  void setSecret(String secret) {
    _encryptionSecret = secret;
    _defaultSalt = secret.hashCode;
  }

  //M10
  /// Converts a [string] to a byte sequence used as secret for AES encryption.
  ///
  /// [size] is the length of the result.
  /// If the conversion of [string] is shorter than [size] the result
  /// will be enlarged with [defaultAdditions].
  Uint8List? stringToBytes(
    String? string, {
    required int size,
    required String defaultAdditions,
  }) {
    Uint8List? rc;
    if (string != null) {
      var string2 = utf8.encode(string);
      if (string2.length < size) {
        string2 +=
            utf8.encode(defaultAdditions.substring(0, size - string2.length));
      } else if (string2.length > size) {
        string2 = string2.sublist(0, size);
      }
      rc = Uint8List.fromList(string2);
    }
    return rc;
  }

  //M10
  /// Creates a byte block with random data.
  static Uint8List createRandomData(int length) {
    final rc = Uint8List(length);
    fillBlockRandomly(rc);
    return rc;
  }

  //M10
  static void fillBlockRandomly(Uint8List data) {
    final random = Random(DateTime.now().microsecondsSinceEpoch ~/ 87321);
    int ix;
    int current;
    for (ix = data.length - 1; ix >= 4; ix -= 4) {
      current = random.nextInt(1 << 32);
      data[ix] = current & 0xff;
      current >>= 8;
      data[ix - 1] = current & 0xff;
      current >>= 8;
      data[ix - 2] = current & 0xff;
      current >>= 8;
      data[ix - 3] = current & 0xff;
    }
    current = random.nextInt(1 << 32);
    while (ix >= 0) {
      data[ix] = current & 0xff;
      current >>= 8;
    }
  }
}

//F/^}/
/// Manages a block (list of bytes) for hiding secrets.
///
/// The block has random data and embedded encrypted data like passwords named
/// "secrets".
/// The secrets will be stored as AES encrypted data with length and checksum.
class DataSafe {
  //M1
  late final Uint8List data;
  //M1
  final Cipher cipher;
  //M1
  int indexMask1;
  //M1
  int indexMask2;
  //M1
  final List<Range> ranges = [];

  //M10
  /// Creates a new data safe with given [data].
  ///
  /// [cipher] is used to encrypt the stored secrets.
  /// [indexMask1] and [indexMask1] are indexes of two random bytes
  /// used to hide the length information.
  DataSafe(this.data, this.cipher, {this.indexMask1 = 0, this.indexMask2 = 1});

  //M10
  /// Creates a new data safe with a given [length].
  ///
  /// [cipher] is used to encrypt the stored secrets.
  /// [indexMask1] and [indexMask1] are indexes of two random bytes
  /// used to hide the length information.
  DataSafe.fromLength(
    int length,
    this.cipher, {
    this.indexMask1 = 0,
    this.indexMask2 = 1,
  }) : data = Uint8List(length);

  //M10
  /// Checks whether a given range with start [index] and [length] contains
  /// the [indexMask1] or [indexMask2].
  bool checkOffset(int index, int length) {
    var rc = index + length <= indexMask1 || index > indexMask1;
    if (!rc) {
      error(
        'range [$index, ${index + length}] contains indexMask1 $indexMask1',
      );
    } else {
      rc = index + length <= indexMask2 || index > indexMask2;
      if (!rc) {
        error(
          'range [$index, ${index + length}] contains indexMask2 $indexMask2',
        );
      }
    }
    return rc;
  }

  //M10
  /// Fills the block with random data.
  void fill() {
    final random = Random(DateTime.now().microsecondsSinceEpoch ~/ 87321);
    var index = data.length - 1;
    int value;
    while (index >= 4) {
      value = random.nextInt(1 << 32);
      data[index] = value % 256;
      value >>= 8;
      data[index - 1] = value % 256;
      value >>= 8;
      data[index - 2] = value % 256;
      value >>= 8;
      data[index - 3] = value % 256;
      index -= 4;
    }
    value = random.nextInt(1 << 32);
    while (index >= 0) {
      data[index] = value % 256;
      value >>= 8;
      index--;
    }
  }

  //M10
  List<ByteCounter> frequency() {
    final statistics = <ByteCounter>[];
    for (int ix = 0; ix < 256; ix++) {
      statistics.add(ByteCounter(ix));
    }
    for (var ix = data.length - 1; ix >= 0; ix--) {
      statistics[data[ix]].count++;
    }
    statistics.sort((a, b) => a.count - b.count);
    return statistics;
  }

  //M10
  void load() {
    ranges.add(Range(indexMask1, 2));
    ranges.add(Range(indexMask2, 2));
  }

  //M10
  /// Reads a 16 bit integer from [offset].
  ///
  /// [masks]: If not null or empty: the stored values are xor-ed with this masks.
  /// Returns -1 on error or the stored value.
  int readInt16({
    required int offset,
    List<int>? masks,
    bool checkOverlapping = true,
  }) {
    var rc = -1;
    if (offset >= data.length - 1) {
      error('storeInt16: offset to high: $offset / ${data.length}');
    } else if (!checkOverlapping || checkOffset(offset, 2)) {
      if (masks == null || masks.isEmpty) {
        rc = data[offset] * 256 + data[offset + 1];
      } else {
        rc = (data[offset] ^ masks[0]) * 256 +
            (data[offset + 1] ^ masks[masks.length == 1 ? 0 : 1]);
      }
    }
    return rc;
  }

  //M10
  /// Reads a secret from [offset].
  ///
  /// If [secret] is not null that secret is take for the decryption.
  /// Otherwise the [cipher.secret].
  /// Returns false if an error has occurred.
  String? readSecret(int offset, {String? secret}) {
    String? rc;
    if (checkOffset(offset, 4 + 16)) {
      /// AES encoded data has a minimum size of 16:
      if (offset + 2 + 2 + 16 > data.length) {
        error('offset too high: $offset/${data.length}');
      } else {
        int offset2 = offset;
        final length = (data[offset2] ^ data[indexMask1]) * 256 +
            (data[offset2 + 1] ^ data[indexMask2]);
        offset2 += 2;
        if (offset + 2 + 2 + length > data.length) {
          error('offset too high: length: $length $offset/${data.length}');
        } else {
          final encoded = Uint8List(length);
          int checksum = 0;
          for (var ix = 0; ix < length; ix++) {
            encoded[ix] = data[offset2++];
            checksum ^= (checksum << 1) + encoded[ix];
          }
          checksum &= 0xffff;
          final storedSum = data[offset2] * 256 + data[offset2 + 1];
          if (storedSum != checksum) {
            error(
              'wrong checksum: length: $length offset: $offset checksum: ${sprintf("%x", [
                    checksum
                  ])}/${sprintf("%x", [storedSum])}}',
            );
          } else {
            rc = cipher.decodeAES(
              data: encoded,
              secret: secret ?? cipher.secret,
            );
          }
        }
      }
    }
    return rc;
  }

  //M10
  /// Displays a statistic of the frequency of the bytes.
  ///
  /// [countResults] is the count of lowest values and highest values.
  void showFrequency(int countResults) {
    final statistics = frequency();
    for (int ix = 0; ix < countResults; ix++) {
      log(
        sprintf(
          "%3d: %02x %4d",
          [ix, statistics[ix].codepoint, statistics[ix].count],
        ),
      );
    }
    log('average: ${data.length ~/ 256}');
    for (int ix = 0; ix < countResults; ix++) {
      final ix2 = 256 - countResults + ix;
      log(
        sprintf(
          "%3d: %02x %4d",
          [ix2, statistics[ix2].codepoint, statistics[ix2].count],
        ),
      );
    }
  }

  //M10
  /// Stores a 16 bit integer [value] at [offset].
  ///
  /// [masks]: If not null or empty: the stored values are xor-ed with this masks.
  /// Returns true on success.
  bool storeInt16({
    required int offset,
    required int value,
    List<int>? masks,
    bool checkOverlapping = true,
  }) {
    var rc = false;
    if (offset >= data.length - 1) {
      error('storeInt16: offset to high: $offset / ${data.length}');
    } else if (value >= 0x10000) {
      error('data not a 16 bit value: $value');
    } else if (!checkOverlapping || checkOffset(offset, 2)) {
      if (masks == null || masks.isEmpty) {
        data[offset] = value >> 8;
        data[offset + 1] = value & 0xff;
      } else {
        data[offset] = (masks[0] ^ (value >> 8)) & 0xff;
        data[offset + 1] = (masks[masks.length == 1 ? 0 : 1] ^ value) & 0xff;
      }
      rc = true;
    }
    return rc;
  }

  //M10
  /// Puts the encoded version of [text] at the position [offset] in the block.
  ///
  /// Returns false if an error has occurred.
  bool storeSecret(int offset, String text) {
    bool rc = true;
    final encoded = cipher.encodeAES(data: text, secret: cipher.secret);
    if (checkOffset(offset, encoded.length + 4)) {
      if (offset + 2 + 2 + encoded.length > data.length) {
        error(
          'offset too high: [$offset, ${offset + 2 + 2 + encoded.length}]/${data.length}',
        );
        rc = false;
      } else {
        int offset2 = offset;
        data[offset2++] = data[indexMask1] ^ (encoded.length >> 8);
        data[offset2++] = data[indexMask2] ^ (encoded.length & 0xff);
        int checksum = 0;
        for (var ix = 0; ix < encoded.length; ix++) {
          data[offset2++] = encoded[ix];
          checksum ^= (checksum << 1) + encoded[ix];
        }
        final checksum2 = checksum & 0xffff;
        data[offset2++] = (checksum2 >> 8) & 0xff;
        data[offset2] = checksum2 & 0xff;
      }
    }
    return rc;
  }

  //M10
  bool testCustom(double data) {
    return true;
  }

  //M10
  /// Reads a secret from [offset].
  ///
  /// Returns false if an error has occurred.
  static String? readSecret2({
    required int offset,
    required Uint8List data,
    required Cipher cipher,
    required int indexMask1,
    required int indexMask2,
  }) {
    String? rc;

    /// AES encoded data has a minimum size of 16:
    if (offset + 2 + 2 + 16 > data.length) {
      error('offset too high: $offset/${data.length}');
    } else {
      int offset2 = offset;
      final length = (data[offset2] ^ data[indexMask1]) * 256 +
          (data[offset2 + 1] ^ data[indexMask2]);
      offset2 += 2;
      if (offset + 2 + 2 + length > data.length) {
        error('offset too high: length: $length $offset/${data.length}');
      } else {
        final encoded = Uint8List(length);
        int checksum = 0;
        for (var ix = 0; ix < length; ix++) {
          encoded[ix] = data[offset2++];
          checksum ^= (checksum << 1) + encoded[ix];
        }
        checksum &= 0xffff;
        final storedSum = data[offset2] * 256 + data[offset2 + 1];
        if (storedSum != checksum) {
          error(
            'wrong checksum: length: $length offset: $offset checksum: ${sprintf("%x", [
                  checksum
                ])}/${sprintf("%x", [storedSum])}}',
          );
        } else {
          rc = cipher.decodeAES(data: encoded, secret: cipher.secret);
        }
      }
    }
    return rc;
  }
}

//F/^}/
/// Stores a range of numbers with [start] and interval [length].
class Range {
  //M1
  final int start;
  //M1
  final int length;
  //M10
  Range(this.start, this.length);

  //M10
  /// Tests whether the [other] range has common values with the instance.
  bool overlaps(Range other) {
    final bool rc;
    if (other.length < length) {
      rc = other.start >= start && other.start < start + length ||
          other.start + length - 1 >= start &&
              other.start + length - 1 < start + length;
    } else {
      rc = start >= other.start && start < other.start + other.length ||
          start + length - 1 >= other.start &&
              start + length - 1 < other.start + other.length;
    }
    return rc;
  }

  //M10
  /// Tests whether [others] ranges has common values with the instance.
  bool overlapsList(List<Range> others) {
    var rc = false;
    for (final other in others) {
      if (overlaps(other)) {
        rc = true;
        break;
      }
    }
    return rc;
  }
}

//F/^}/
enum SecretEntity {
  entityOffsetIndexMask0,
  entityOffsetIndexMask1,
  entityOffsetIndexMask2,
  entityOffsetSecret,
  entityCodepointMask,
}

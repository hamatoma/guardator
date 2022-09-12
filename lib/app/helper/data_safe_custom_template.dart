import 'dart:io';
import 'dart:math';

import 'cipher.dart';
import 'cipher_io.dart';

//F/;/
const globalARandom2 = [
  3601222191,
  2495415464,
  877211394,
  2403524173,
  3305935704,
  1199979783,
  4123707724
];
//F/;/
/// This data helps to hide text data in the program to make it difficult to
/// debug the program.
///
/// Take you own values! Use it for scrambling texts.
/// The number of masks may be changed.
/// If you change that you must renew the following constants starting with
/// "text": [textDefaultSecret], [textFileLinux]...
/// Create it with:
/// scrampler codepoints --masks=0x11,0x08,0x19,0x64,0x20,0x04,0x19,0x91,0x58 <text>
const globalMasks = [0x11, 0x08, 0x19, 0x64, 0x20, 0x04, 0x19, 0x91, 0x58];

//F/;/
const globalZRandom1 = [
  1979118074,
  4941654139,
  2065733203,
  1396123964,
  894825863,
  12349922,
];
//F/;/
/// The default password for encrypting the secrets in the data safe.
///
/// Take you own secret! And than create the following data with:
/// scrambler codepoints --masks=0x11,0x08,0x19,0x64,0x20,0x04,0x19,0x91,0x58 <text>
/// text: NEVER.find.It,out4836
const textDefaultSecret0 = [
  95,
  77,
  79,
  33,
  114,
  42,
  127,
  248,
  54,
  117,
  38,
  80,
  16,
  12,
  107,
  108,
  229,
  108,
  41,
  59,
  47
];
//F/;/
// My.Secret
const textDefaultSecret1 = [92, 113, 55, 55, 69, 103, 107, 244, 44];

//F/;/
/// The linux name of the data safe file.
///
// text: /etc/guardator/datasafe.data
const textFileLinux = [
  62,
  109,
  109,
  7,
  15,
  99,
  108,
  240,
  42,
  117,
  105,
  109,
  11,
  82,
  43,
  125,
  240,
  44,
  112,
  123,
  120,
  2,
  69,
  42,
  125,
  240,
  44,
  112
];

//F/;/
/// The windows name of the data safe file.
///
// text: c:\config\guardator\datasafe.data
const textFileWindows = [
  114,
  50,
  69,
  7,
  79,
  106,
  127,
  248,
  63,
  77,
  111,
  108,
  5,
  82,
  96,
  120,
  229,
  55,
  99,
  84,
  125,
  5,
  84,
  101,
  106,
  240,
  62,
  116,
  38,
  125,
  5,
  84,
  101
];

//F/;/
// Invalid configuration data. Please reinstall guardator.
const List<int> textReinstall = [
  88,
  102,
  111,
  5,
  76,
  109,
  125,
  177,
  59,
  126,
  102,
  127,
  13,
  71,
  113,
  107,
  240,
  44,
  120,
  103,
  119,
  68,
  68,
  101,
  109,
  240,
  118,
  49,
  88,
  117,
  1,
  65,
  119,
  124,
  177,
  42,
  116,
  97,
  119,
  23,
  84,
  101,
  117,
  253,
  120,
  118,
  125,
  120,
  22,
  68,
  101,
  109,
  254,
  42,
  63
];

//F/;/
/// The linux file path separator.
///
/// text: '/'
const textSeparator = [62];

//F/^}/
/// The customized data safe.
///
/// Each system administrator should modify the constants starting with 'default'
/// ([defaultReferenceIndexMask0], [defaultReferenceIndexMask1] ...)
/// in this class to create an individual data safe (different to the published
/// sources).
class DataSafeCustom extends DataSafeIO {
  static const defaultReferenceIndexMask0 = 1793;
  static const defaultReferenceIndexMask1 = 47;
  static const defaultReferenceIndexMask2 = 12;
  static const defaultReferenceSecret0 = 1234;
  static const defaultReferenceSecret1 = 4321;
  static DataSafeCustom? _instance;

  int indexMask0 = 0;
  int indexSecret0 = 0;
  int indexSecret1 = 0;
  factory DataSafeCustom() {
    _instance ??= DataSafeCustom.defaultInstance();
    return _instance!;
  }

  DataSafeCustom.defaultInstance()
      : super.fromFile(
          defaultFilename(),
          Cipher(),
          indexMask1: -1,
          indexMask2: -1,
        ) {
    //M1
    if (indexMask1 < 0) {
      load();
    }
    //M2
    final secret0 =
        fromCodepoints(data: textDefaultSecret0, masks: globalMasks);
    //M2
    final secret1 =
    fromCodepoints(data: textDefaultSecret1, masks: globalMasks);
    //M3
    final secret0a = readSecret(indexSecret0, secret: secret0);
    //M3
    final secret1a = readSecret(indexSecret1, secret: secret1);
    //M4
    if (secret0a == null) {
      throw FormatException(
        fromCodepoints(data: textReinstall, masks: globalMasks),
      );
    }
    //M4
    if (secret1a == null) {
      throw FormatException(
        fromCodepoints(data: textReinstall, masks: globalMasks),
      );
    }
    //M5
    cipher.setSecret(secret0);
  }

  //M10
  /// Reads a data safe from a file named [filename].
  ///
  /// [cipher] is used to encrypt the stored secrets.
  /// [indexMask1] and [indexMask1] are indexes of two random bytes
  /// used to hide the length information.
  DataSafeCustom.fromFile({
    required String filename,
    Cipher? cipher,
    super.indexMask1 = defaultReferenceIndexMask1,
    super.indexMask2 = defaultReferenceIndexMask2,
  }) : super.fromFile(
          filename,
          cipher ?? Cipher(secret: defaultSecret0()),
        ) {
    load();
  }

  //M10
  /// Creates a new data safe with a given [length].
  ///
  /// [cipher] is used to encrypt the stored secrets.
  DataSafeCustom.fromLength(
    super.length,
    super.cipher, {
    super.indexMask1 = defaultReferenceIndexMask1,
    super.indexMask2 = defaultReferenceIndexMask2,
  }) : super.fromLength();

  //M10
  DataSafeCustom.internal(
    super.data,
    super.cipher, {
    super.indexMask1 = defaultReferenceIndexMask1,
    super.indexMask2 = defaultReferenceIndexMask2,
  }) {
    load();
  }

  //M10
  @override
  void load() {
    super.load();
    indexMask0 = readInt16(
      offset: defaultReferenceIndexMask0,
      masks: globalMasks,
      checkOverlapping: false,
    );
    ranges.add(Range(defaultReferenceIndexMask0, 2));
    ranges.add(Range(indexMask0, 2));
    indexMask1 = readInt16(
      offset: defaultReferenceIndexMask1,
      masks: globalMasks,
      checkOverlapping: false,
    );
    ranges.add(Range(defaultReferenceIndexMask1, 2));
    indexMask2 = readInt16(
      offset: defaultReferenceIndexMask2,
      masks: globalMasks,
      checkOverlapping: false,
    );
    ranges.add(Range(defaultReferenceIndexMask2, 2));
    indexSecret0 = readInt16(
      offset: defaultReferenceSecret0,
      masks: globalMasks,
      checkOverlapping: false,
    );
    ranges.add(Range(defaultReferenceSecret0, 2));
    ranges.add(Range(indexSecret0, 2 + 32 + 2));
    indexSecret1 = readInt16(
      offset: defaultReferenceSecret1,
      masks: globalMasks,
      checkOverlapping: false,
    );
    ranges.add(Range(defaultReferenceSecret1, 2));
    ranges.add(Range(indexSecret1, 2 + 32 + 2));
  }

  //M10
  String status() {
    const rc = '';
    /*
    final rc = '''
indexMask0: reference $defaultReferenceIndexMask0 value: $indexMask0 / ${readInt16(offset: defaultReferenceIndexMask0, masks: globalMasks)}
indexMask1: reference $defaultReferenceIndexMask1 value: $indexMask1 / ${readInt16(offset: defaultReferenceIndexMask1, masks: globalMasks)}
indexMask2: reference $defaultReferenceIndexMask2 value: $indexMask2 / ${readInt16(offset: defaultReferenceIndexMask2, masks: globalMasks)}
indexSecr*: reference $defaultReferenceSecret value: $indexSecret / ${readInt16(offset: defaultReferenceSecret, masks: globalMasks)}
masks: ${globalMasks.map((e) => sprintf('0x%s', [e])).join(',')}
''';
    */
    return rc;
  }

  //M10
  @override
  bool testCustom(double data) {
    const rc = true;
    return rc;
  }

  //M10
  static bool checkPreconditions({bool throwOnError = true}) {
    var rc = true;
    if (!File(defaultFilename()).existsSync()) {
      if (throwOnError) {
        throw const FormatException('missing data file. Reinstall guardator.');
      } else {
        rc = false;
      }
    }
    return rc;
  }

  //M10
  static String defaultFilename() {
    final filename = Platform.pathSeparator ==
            fromCodepoints(data: textSeparator, masks: globalMasks)
        ? fromCodepoints(data: textFileLinux, masks: globalMasks)
        : fromCodepoints(data: textFileWindows, masks: globalMasks);
    return filename;
  }

  //M10
  static String defaultSecret0() {
    final rc = fromCodepoints(data: textDefaultSecret0, masks: globalMasks);
    return rc;
  }

  //M10
  static String defaultSecret1() {
    final rc = fromCodepoints(data: textDefaultSecret1, masks: globalMasks);
    return rc;
  }

  //M10
  static void initFromScratch({
    required String secret0,
    required String secret1,
    String? file,
    int size = 4092,
  }) {
    final safe = DataSafeCustom.fromLength(size, Cipher());
    safe.cipher.setSecret(
      fromCodepoints(data: textDefaultSecret0, masks: globalMasks),
    );
    safe.fill();
    final random = Random(
      DateTime.now().microsecondsSinceEpoch ~/
          (globalARandom2[0] % 1023 + globalZRandom1[1] % 4091),
    );
    var range = Range(2 + random.nextInt(size - 4), 2);
    safe.indexMask0 = range.start;
    safe.storeInt16(
      offset: defaultReferenceIndexMask0,
      value: range.start,
      masks: globalMasks,
      checkOverlapping: false,
    );
    final occupied = [range];
    while ((range = Range(2 + random.nextInt(size - 4), 2))
        .overlapsList(occupied)) {
      // do nothing
    }
    safe.indexMask1 = range.start;
    safe.storeInt16(
      offset: defaultReferenceIndexMask1,
      value: range.start,
      masks: globalMasks,
      checkOverlapping: false,
    );
    occupied.add(range);
    while ((range = Range(2 + random.nextInt(size - 4), 2))
        .overlapsList(occupied)) {
      // do nothing
    }
    safe.indexMask2 = range.start;
    safe.storeInt16(
      offset: defaultReferenceIndexMask2,
      value: range.start,
      masks: globalMasks,
      checkOverlapping: false,
    );
    occupied.add(range);
    while ((range = Range(2 + random.nextInt(size - 4), 2 + 32 + 2))
        .overlapsList(occupied)) {
      // do nothing
    }
    safe.indexSecret0 = range.start;
    safe.storeInt16(
      offset: defaultReferenceSecret0,
      value: range.start,
      masks: globalMasks,
      checkOverlapping: false,
    );
    safe.storeSecret(range.start, secret0);
    while ((range = Range(2 + random.nextInt(size - 4), 2 + 32 + 2))
        .overlapsList(occupied)) {
      // do nothing
    }
    safe.indexSecret1 = range.start;
    safe.storeInt16(
      offset: defaultReferenceSecret1,
      value: range.start,
      masks: globalMasks,
      checkOverlapping: false,
    );
    safe.storeSecret(range.start, secret1);
    safe.load();
    safe.write(file ?? defaultFilename());
  }
}

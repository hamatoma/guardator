import 'dart:io';
import 'dart:math';

import 'package:args/args.dart';

import 'cipher.dart';
import 'cipher_io.dart';
import 'data_safe_custom.dart';
import 'string_tools.dart';

/// Reads the [args] and does the command.
void main(List<String> args) {
  final parser = ArgParser();
  lastResultLines.clear();
  //M1
  parser.addFlag(
    'verbose',
    abbr: 'v',
    help: 'shows more information',
  );
  //M3
  parser.addCommand('codepoints', prepareCodepoint());
  //M3
  parser.addCommand('shuffle', prepareShuffle());
  //M3
  parser.addCommand('create-safe', prepareCreate());
  //M3
  parser.addCommand('patch-safe', preparePatchSafe());
  //M3
  parser.addCommand('store-int16', prepareStoreInt16());
  //M3
  parser.addCommand('random', prepareRandom());
  //M3
  parser.addCommand('initialize', prepareInit());
  //M5
  try {
    final results = parser.parse(args);
    //M6
    if (results.command == null) {
      usage('missing <command>', parser);
    } else {
      //M9
      final mode = results.command!.name!;
      //M11
      if ('codepoints'.startsWith(mode)) {
        lastResultLines = codepoints(results.command!, parser);
        if (!underTest) {
          log(lastResultLines.join('\n'));
        }
      } else if ('shuffle'.startsWith(mode)) {
        lastResultLines = shuffle(
          results.command!,
          parser,
          results.command!['reverse'] as bool
              ? reverseRangeBuilder
              : randomRangeBuilder,
        );
      } else if ('create-safe'.startsWith(mode)) {
        final rc = createSafe(
          results.command!,
          parser,
        );
        lastResultLines = [if (rc) 'OK' else 'ERROR'];
      } else if ('patch-safe'.startsWith(mode)) {
        final rc = patchSafe(
          results.command!,
          parser,
        );
        lastResultLines = [if (rc) 'OK' else 'ERROR'];
      } else if ('store-int16'.startsWith(mode)) {
        final rc = storeInt16(
          results.command!,
          parser,
        );
        lastResultLines = [if (rc) 'OK' else 'ERROR'];
      } else if ('random'.startsWith(mode)) {
        final rc = randomCommand(
          results.command!,
          parser,
        );
        lastResultLines = [if (rc) 'OK' else 'ERROR'];
      } else if ('initialize'.startsWith(mode)) {
        final rc = initialize(
          results.command!,
          parser,
        );
        lastResultLines = [if (rc) 'OK' else 'ERROR'];
      } else {
        usage('unknown mode: $mode', parser);
      }
    }
  } on FormatException catch (exc) {
    usage('$exc', parser);
  }
}

// scrambler codepoints --masks=0x24,0x49,0x22,0xa7,0xb3
const List<int> globalMasks = [0x24, 0x49, 0x22, 0xa7, 0xb3];
// Password (nothing is displayed when you type the text):
const List<int> textPasswordPrompt = [
  116,
  40,
  81,
  212,
  196,
  75,
  59,
  70,
  135,
  155,
  74,
  38,
  86,
  207,
  218,
  74,
  46,
  2,
  206,
  192,
  4,
  45,
  75,
  212,
  195,
  72,
  40,
  91,
  194,
  215,
  4,
  62,
  74,
  194,
  221,
  4,
  48,
  77,
  210,
  147,
  80,
  48,
  82,
  194,
  147,
  80,
  33,
  71,
  135,
  199,
  65,
  49,
  86,
  142,
  137
];
// Sorry!
const List<int> textSorry = [119, 38, 80, 213, 202, 5];

//F/^;/
List<String> lastResultLines = [];

//F/^;/
bool underTest = false;

/// Handles the command "codepoints".
List<String> codepoints(ArgResults argResults, ArgParser parser) {
  final List<String> rc = <String>[];
  final masks = getMasks(argResults);
  if (masks == null) {
    rc.add('ERROR');
  } else {
    final buffer = StringBuffer();
    for (final arg in argResults.rest) {
      buffer.clear();
      buffer.write('[');
      var ixMasks = 0;
      for (var ix = 0; ix < arg.length; ix++) {
        for (var ix2 = 0; ix2 < arg[ix].codeUnits.length; ix2++) {
          var value = arg[ix].codeUnits[ix2];
          if (masks.isNotEmpty) {
            if (ixMasks >= masks.length) {
              ixMasks = 0;
            }
            value ^= masks[ixMasks++];
          }
          buffer.write(value);
          if (ix < arg.length - 1 || ix2 < arg[ix].codeUnits.length - 1) {
            buffer.write(',');
          }
        }
      }
      buffer.write(']');
      rc.add(buffer.toString());
    }
  }
  return rc;
}

/// Handles the command "create-safe".
bool createSafe(
  ArgResults argResults,
  ArgParser parser,
) {
  var rc = true;
  if (argResults.rest.isEmpty) {
    usage('missing <output>', parser);
    rc = false;
  } else {
    final cipher = Cipher();
    if (argResults['secret'] != null) {
      cipher.setSecret(argResults['secret']! as String);
    }
    final safe = DataSafeCustom.fromLength(
      int.parse(argResults['size']! as String),
      cipher,
    );
    safe.fill();
    final output = File(argResults.rest[0]);
    final upperbound = (argResults.rest.length - 1) ~/ 2 * 2 + 1;
    for (var ix = 1; ix < upperbound; ix += 2) {
      var arg = argResults.rest[ix];
      final offset = int.tryParse(arg);
      if (offset == null) {
        usage('offset in argument ${1 + ix} is not an integer: $arg', parser);
        rc = false;
        break;
      }
      arg = argResults.rest[ix + 1];
      safe.storeSecret(offset, arg);
    }
    if (rc) {
      try {
        output.writeAsBytesSync(safe.data);
        log("written: $output");
      } on Exception catch (exc) {
        error('$exc');
        rc = false;
      }
    }
  }
  return rc;
}

/// Gets the values of the option 'masks'.
///
/// Returns null on error or an empty list if no option is given.
List<int>? getMasks(ArgResults argResults) {
  List<int>? masks = <int>[];
  if (argResults['masks'] != null) {
    final parts = (argResults['masks'] as String).split(',');
    for (var ix = 0; masks != null && ix < parts.length; ix++) {
      final number = stringToInt(parts[ix]);
      if (number == null) {
        error('mask at position ${ix + 1} is not an integer: ${parts[ix]}');
        masks = null;
        break;
      } else if (number > 255) {
        error('mask on position ${ix + 1} > 255: $number');
        masks = null;
      } else {
        masks.add(number);
      }
    }
  }
  return masks;
}

/// Handles the 'random' command.
bool initialize(ArgResults argResults, ArgParser parser) {
  var rc = false;
  if (argResults.rest.isNotEmpty) {
    usage('too many arguments', parser);
  } else {
    final secret0 = argResults['secret'];
    final secret0b =
        secret0 == null ? DataSafeCustom.defaultSecret0() : secret0 as String;
    final secret1 = argResults['secret2'];
    final secret1b =
        secret1 == null ? DataSafeCustom.defaultSecret1() : secret1 as String;
    final file = argResults['file'] as String;
    final force = argResults['force'] as bool;
    final size = stringToInt(argResults['size'] as String);
    final exists = File(file).existsSync();
    if (size == null) {
      usage('<size> ist not an integer: ${argResults["size"]}', parser);
    } else if (!force && exists) {
      error('target file $file already exist. Use --force to overwrite.');
    } else {
      final secret = DataSafeCustom.defaultSecret1();
      if (underTest) {
        rc = true;
      } else {
        log(fromCodepoints(data: textPasswordPrompt, masks: globalMasks));
        if (readPassword() != secret) {
          error(fromCodepoints(data: textSorry, masks: globalMasks));
        } else {
          rc = true;
        }
      }
      if (rc) {
        DataSafeCustom.initFromScratch(
          secret0: secret0b,
          secret1: secret1b,
          file: file,
          size: size,
        );
      }
    }
  }
  return rc;
}

//F/^}/
/// Handles the command "patch-safe".
bool patchSafe(
  ArgResults argResults,
  ArgParser parser,
) {
  var rc = true;
  if (argResults.rest.isEmpty) {
    usage('missing <file>', parser);
    rc = false;
  } else {
    final file = argResults.rest[0];
    if (!File(file).existsSync()) {
      usage('<file> $file does not exists', parser);
      rc = false;
    } else {
      final cipher = Cipher();
      final safe = DataSafeIO.fromFile(file, cipher);
      final upperbound = (argResults.rest.length - 1) ~/ 2 * 2 + 1;
      for (var ix = 1; ix < upperbound; ix += 2) {
        var arg = argResults.rest[ix];
        final offset = int.tryParse(arg);
        if (offset == null) {
          usage('offset in argument ${1 + ix} is not an integer: $arg', parser);
          rc = false;
          break;
        }
        arg = argResults.rest[ix + 1];
        safe.storeSecret(offset, arg);
      }
      if (rc) {
        rc = safe.write(file);
      }
    }
  }
  return rc;
}

ArgParser prepareCodepoint() {
  //M2
  final codepointParser = ArgParser();
  //M3
  codepointParser.addOption(
    'masks',
    abbr: 'm',
    help:
        'A comma separated list of values that will be xor-ed to the codepoints.',
  );
  return codepointParser;
}

//F/^}/
ArgParser prepareCreate() {
  //M2
  final createSafeParser = ArgParser();
  //M3
  createSafeParser.addOption(
    'size',
    abbr: 'z',
    help: 'The size of the output file.',
    defaultsTo: '65536',
  );
  //M3
  createSafeParser.addOption(
    'secret',
    abbr: 's',
    help: 'The secret ("passphrase") for encryption.',
  );
  //M3
  createSafeParser.addOption(
    'secret2',
    abbr: 'S',
    help: 'The password for execution.',
  );
  //M3
  createSafeParser.addOption(
    'file',
    abbr: 'f',
    help: 'the file of the data safe.',
    defaultsTo: DataSafeCustom.defaultFilename(),
  );
  //M3
  createSafeParser.addFlag(
    'force',
    abbr: 'F',
    help: 'forces overwriting the existing file.',
  );
  return createSafeParser;
}

//F/^}/
//F/^}/
ArgParser prepareInit() {
  //M2
  final initParser = ArgParser();
  //M3
  initParser.addOption(
    'file',
    abbr: 'f',
    help: 'the file of the data safe.',
    defaultsTo: DataSafeCustom.defaultFilename(),
  );
  //M3
  initParser.addOption(
    'secret',
    abbr: 's',
    help: 'the secret used for en/decrypting storage data.',
  );
  //M3
  initParser.addOption(
    'secret2',
    abbr: '2',
    help: 'the password used for execution of critical commands.',
  );
  //M3
  initParser.addOption(
    'size',
    abbr: 'z',
    help: 'the size of the data safe file.',
    defaultsTo: '4092',
  );
  //M3
  initParser.addFlag(
    'force',
    abbr: 'F',
    help: 'forces overwriting the existing file.',
  );
  return initParser;
}

//F/^}/
//F/^}/
ArgParser preparePatchSafe() {
  //M2
  final patchSafeParser = ArgParser();
  //M3
  patchSafeParser.addOption(
    'secret',
    abbr: 'S',
    help: 'The secret ("passphrase") for encryption.',
  );
  return patchSafeParser;
}

//F/^}/
//F/^}/
ArgParser prepareRandom() {
  //M2
  final randomParser = ArgParser();
  //M3
  randomParser.addOption(
    'max-value',
    abbr: 'M',
    help: 'the maximum (including) value of the created numbers.',
    defaultsTo: '4294967295',
  );
  //M3
  randomParser.addOption(
    'min-value',
    abbr: 'm',
    help: 'the minimum value of the created numbers.',
    defaultsTo: '0',
  );
  //M3
  randomParser.addOption(
    'separator',
    abbr: 's',
    help: 'the separator between the created number.',
    defaultsTo: ',',
  );
  return randomParser;
}

//F/^}/
ArgParser prepareShuffle() {
  //M2
  final shuffleParser = ArgParser();
  // M4
  shuffleParser.addFlag(
    'reverse',
    abbr: 'h',
    help: 'Sorts ranges in reverse order (for testing).',
  );
  return shuffleParser;
}

//F/^}/
ArgParser prepareStoreInt16() {
  //M2
  final storeInt16Parser = ArgParser();
  //M3
  storeInt16Parser.addOption(
    'masks',
    abbr: 'm',
    help:
        'A comma separated list of values that will be xor-ed to the stored data.',
  );
  return storeInt16Parser;
}

//F/^}/
/// Handles the 'random' command.
bool randomCommand(ArgResults argResults, ArgParser parser) {
  var rc = false;
  if (argResults.rest.isEmpty) {
    usage('missing <count>', parser);
  } else {
    final count = stringToInt(argResults.rest[0]);
    if (count == null) {
      usage('<count> is not an integer: $count', parser);
    } else {
      final minimum = stringToInt(argResults['min-value'] as String);
      final maximum = stringToInt(argResults['max-value'] as String);
      if (minimum == null) {
        usage(
          '--min-value is not an integer: ${argResults['min-value'] as String}',
          parser,
        );
      } else if (maximum == null) {
        usage(
          '--max-value is not an integer: ${argResults['max-value'] as String}',
          parser,
        );
      } else {
        rc = true;
        final separator = argResults['separator'];
        final rand = Random(DateTime.now().microsecondsSinceEpoch);
        final buffer = StringBuffer();
        for (var ix = 0; ix < count; ix++) {
          final value = minimum + rand.nextInt(maximum - minimum);
          if (buffer.isNotEmpty) {
            buffer.write(separator);
          }
          buffer.write('$value');
        }
        log(buffer.toString());
      }
    }
  }
  return rc;
}

//F/^}/
/// Returns a list of permutated serial numbers from 0 to [count] - 1.
///
/// Example: count = 3: [1, 0, 2];
List<int> randomRangeBuilder(int count) {
  final rc = reverseRangeBuilder(count);
  rc.shuffle();
  return rc;
}

//F/^}/
/// Reads a string ending with an newline from stdin.
String readPassword() {
  final safe = stdin.echoMode;
  stdin.echoMode = false;
  final rc = stdin.readLineSync();
  stdin.echoMode = safe;
  return rc ?? '';
}

/// Returns a list of serial numbers from [count] - 1 to 0.
///
/// Example: count = 3: [2, 1, 0];
List<int> reverseRangeBuilder(int count) {
  final rc = <int>[];
  var count2 = count;
  while (count2 > 0) {
    rc.add(--count2);
  }
  return rc;
}

/// Handles the command "shuffle".
List<String> shuffle(
  ArgResults argResults,
  ArgParser parser,
  RangeBuilder? shuffleRangeBuilder,
) {
  var lines = <String>[];
  if (argResults.rest.length != 2) {
    usage('missing <output>', parser);
    if (underTest) {
      lines = lastResultLines;
    }
  } else {
    final input = File(argResults.rest[0]);
    final output = File(argResults.rest[1]);
    if (!input.existsSync()) {
      error('missing input file ${input.path}');
      lines.add('ERROR');
    } else {
      final shuffler = Shuffler(input);
      shuffler.buildFileBlocks();
      shuffler.mix(
        argResults['reverse']! as bool
            ? reverseRangeBuilder
            : randomRangeBuilder,
      );
      lines = shuffler.join();
    }
    try {
      output.writeAsStringSync(lines.join('\n'));
    } on FileSystemException catch (exc) {
      error('$exc');
      lines = ['ERROR'];
    }
  }
  return lines;
}

//F/^}/
/// Handles the command "store-int16".
bool storeInt16(
  ArgResults argResults,
  ArgParser parser,
) {
  var rc = true;
  if (argResults.rest.isEmpty) {
    usage('missing <file>', parser);
    rc = false;
  } else {
    final file = argResults.rest[0];
    if (!File(file).existsSync()) {
      usage('<file> $file does not exists', parser);
      rc = false;
    } else {
      final masks = getMasks(argResults);
      final cipher = Cipher();
      final safe = DataSafeIO.fromFile(file, cipher);
      final upperbound = (argResults.rest.length - 1) ~/ 2 * 2 + 1;
      for (var ix = 1; ix < upperbound; ix += 2) {
        var arg = argResults.rest[ix];
        final offset = int.tryParse(arg);
        if (offset == null) {
          usage('offset in argument ${1 + ix} is not an integer: $arg', parser);
          rc = false;
          break;
        }
        arg = argResults.rest[ix + 1];
        final number = stringToInt(arg);
        if (number == null) {
          usage('argument ${ix + 2}: not an integer: $arg', parser);
          rc = false;
          break;
        } else if (number >= 0x10000) {
          usage('argument ${ix + 2}: is to large: $arg', parser);
          rc = false;
          break;
        } else {
          rc = safe.storeInt16(offset: offset, value: number, masks: masks);
        }
      }
      if (rc) {
        rc = safe.write(file);
      }
    }
  }
  return rc;
}

//F/^}/
/// Prints an usage message.
void usage(String message, ArgParser parser) {
  if (underTest) {
    lastResultLines.clear();
    lastResultLines.add(message);
  } else {
    log('''
Usage: scrambler <command> <args_and_opts>'
  Modifies source code.
''');
    log(parser.usage);
    log('''
scrambler codepoints <text1> [<text2> ...]
  Shows the codepoints of  <textN>.''');
    log(parser.commands['codepoints']!.usage);
    log('''
scrambler create-safe <output> <offset1> <string1> [<offset2> <string2>...]
  Creates a file <output> with random binary data 
    and embedded ciphered <stringN> at <offsetN>''');
    log(parser.commands['create-safe']!.usage);
    log('''
scrambler initialize [<opts>]
  Creates a new standard customized data safe file (with two secrets).''');
    log(parser.commands['initialize']!.usage);
    log('''
scrambler patch-safe [<opts>] <file> [[<offset1> <secret1> [<offset2> <secret2> ...]
  Modifies an existing data safe named <file> with <secretN> at offset <offsetN>.''');
    log(parser.commands['patch-safe']!.usage);
    log('''
scrambler random <count>
  Creates and shows <count> random numbers.''');
    log(parser.commands['random']!.usage);
    log('''
scrambler shuffle <input> <output>
  Reorders source code from file <input> into file <output>.''');
    log(parser.commands['shuffle']!.usage);
    log('''
scrambler store-int16 <file> <offset> <value>
  Stores a 16 bit [value] at [offset] into file <file>.''');
    log(parser.commands['store-int16']!.usage);
  } // ! underTest
  error(message);
  if (!underTest) {
    exit(1);
  }
}

//F/^}/;
typedef RangeBuilder = List<int> Function(int count);

//F/^}/;
/// Stores a code block.
class CodeBlock {
  int id;
  List<String> lines;
  CodeBlock(this.id, this.lines);
}

//F/^}/;
/// Manages a part of the source code file that can be moved to another place.
class FileBlock {
  //M1
  final int id;
  //M1
  final List<String> lines;
  //M1
  // The lines above the method blocks.
  List<String> header = [];
  //M1
  // The lines below the method blocks.
  List<String> footer = [];
  //M1
  /// Stores the [MethodBlock]s ot the file block.
  final List<MethodBlock> methodBlocks = <MethodBlock>[];
  //M1
  // The absolute linenumber of the first line belonging to the file block.
  final int lineOffset;
  //M5
  FileBlock(this.id, this.lines, this.lineOffset);
  //M10
  /// Parses the [lines] and extracts the [MethodBlock]s.
  bool buildMethodBlocks() {
    const rc = true;
    // ..........................1...12..3...32
    final pattern = RegExp(r'^\s*//M(\d+)(\.(\d+))?$');
    final endPattern = RegExp(r'^\s*//MEnd');
    var start = 0;
    var lineIndex = -1;
    var lastId = -1;
    var blockId = 0;
    MethodBlock? currentBlock;
    for (final line in lines) {
      lineIndex++;
      if (line.trim().isEmpty) {
        continue;
      }
      final matcher = pattern.firstMatch(line);
      if (matcher != null) {
        if (lastId == -1) {
          header = lines.sublist(0, lineIndex);
          start = lineIndex;
          lastId = 0;
        }
        var newId = 1000 * int.parse(matcher.group(1)!);
        String? group3;
        if (matcher.groupCount >= 3 && (group3 = matcher.group(3)) != null) {
          newId += int.parse(group3!);
        }
        if (lastId == newId) {
          currentBlock!.addBlock(lines.sublist(start, lineIndex));
          start = lineIndex;
        } else {
          if (currentBlock != null) {
            currentBlock.addBlock(lines.sublist(start, lineIndex));
            start = lineIndex;
          }
          currentBlock = MethodBlock(blockId++);
          methodBlocks.add(currentBlock);
          lastId = newId;
        }
      } else {
        if (endPattern.hasMatch(line)) {
          if (currentBlock != null) {
            currentBlock.addBlock(lines.sublist(start, lineIndex));
            start = lineIndex;
            break;
          }
        }
      }
    }
    footer = lines.sublist(start);
    return rc;
  }

  //M10
  /// Combines the lines for writing.
  List<String> join() {
    final rc = header;
    for (final block in methodBlocks) {
      rc.addAll(block.join());
    }
    rc.addAll(footer);
    return rc;
  }

  //M10
  /// Reorders the codeblocks.
  ///
  /// [rangeBuilder] implements the algorithm to shuffle.
  void mix(RangeBuilder rangeBuilder) {
    for (final block in methodBlocks) {
      block.mix(rangeBuilder);
    }
  }
  //MEnd
}

//F/^}/
/// Manages a part of a file block containing code blocks.
///
/// A [MethodBlock] is written in the same order as in the source, but the
/// [CodeBlock]s stored in [codeBlocks] can be written in another order.
/// Example: <code>a = 123;</code> and <code>b = 'hi';</code> can be swapped
/// without breaking the program.
class MethodBlock {
  //M1
  final int id;
  //M1
  int blockId = 0;
  //M1
  List<String> header = [];
  //M1
  List<String> footer = [];
  //M1
  /// The list of codeblocks that can be written in any order.
  List<CodeBlock> codeBlocks = [];
  //M1
  MethodBlock(this.id);
  //M10
  /// Adds a [CodeBlock] containing the [lines].
  void addBlock(List<String> lines) =>
      codeBlocks.add(CodeBlock(++blockId, lines));

  //M10
  /// Combines all lines of this instance for writing.
  List<String> join() {
    final rc = header;
    for (final block in codeBlocks) {
      rc.addAll(block.lines);
    }
    rc.addAll(footer);
    return rc;
  }

  //M10
  /// Reorders the codeblocks.
  ///
  /// [rangeBuilder] implements the algorithm to shuffle.
  void mix(RangeBuilder rangeBuilder) {
    final newList = <CodeBlock>[];
    final newOrder = rangeBuilder(codeBlocks.length);
    for (final index in newOrder) {
      final block = codeBlocks[index];
      newList.add(block);
    }
    codeBlocks = newList;
  }
  //MEnd
}

//F/^}/;
class Shuffler {
  //M1
  List<String> lines = <String>[];
  //M1
  List<FileBlock> fileBlocks = [];
  //M1
  List<String> header = [];
  //M1
  final File file;
  //M5
  Shuffler(this.file) {
    read();
  }
  //M10
  bool buildFileBlocks() {
    var rc = true;
    final pattern = RegExp(r'^//F/(.*)/$');
    var start = 0;
    var lineIndex = -1;
    RegExp? currentPattern;
    int id = 0;
    var linesBehindEnd = true;
    for (final line in lines) {
      lineIndex++;
      if (line.trim().isEmpty) {
        continue;
      }
      final matcher = pattern.firstMatch(line);
      if (matcher != null) {
        if (currentPattern == null) {
          header = lines.sublist(0, lineIndex);
          start = lineIndex;
        } else {
          if (linesBehindEnd) {
            fileBlocks.add(
              FileBlock(++id, lines.sublist(start, lineIndex), start),
            );
            start = lineIndex;
          }
        }
        currentPattern = RegExp(matcher.group(1)!);
      } else {
        if (currentPattern != null && currentPattern.hasMatch(line)) {
          fileBlocks
              .add(FileBlock(++id, lines.sublist(start, lineIndex + 1), start));
          start = lineIndex + 1;
          linesBehindEnd = false;
        } else {
          linesBehindEnd = true;
        }
      }
    }
    if (rc) {
      if (currentPattern == null) {
        header = lines;
      } else if (start < lineIndex) {
        fileBlocks
            .add(FileBlock(++id, lines.sublist(start, lineIndex), lineIndex));
      }
      for (final block in fileBlocks) {
        if (!block.buildMethodBlocks()) {
          rc = false;
          break;
        }
      }
    }
    return rc;
  }

  //M10
  List<String> join() {
    final rc = header;
    for (final block in fileBlocks) {
      rc.addAll(block.join());
    }
    final pattern = RegExp(r'\d+ /\*RAND-INT\*/');
    var seed = DateTime.now().microsecond;
    for (var ix = 0; ix < rc.length; ix++) {
      final line = rc[ix];
      final matcher = pattern.firstMatch(line);
      if (matcher != null) {
        rc[ix] = line.replaceAll(matcher.group(0)!, '$seed /* RAND */');
        seed = seed * 7 + 0x123491 % 0x7ff0000;
      }
    }
    if (rc.length != lines.length) {
      error(
        'join(): different length: rc: ${rc.length} lines: ${lines.length}',
      );
    }
    return rc;
  }

  //M10
  void mix(RangeBuilder rangeBuilder) {
    final newList = <FileBlock>[];
    final newOrder = rangeBuilder(fileBlocks.length);
    for (final index in newOrder) {
      final block = fileBlocks[index];
      block.mix(rangeBuilder);
      newList.add(block);
    }
    fileBlocks = newList;
  }

  //M10
  void read() {
    lines = file.readAsLinesSync();
  }
  //MEnd
}

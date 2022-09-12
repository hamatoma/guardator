import 'dart:io';

import 'package:args/args.dart';

import 'storage.dart';
import 'string_tools.dart';

//F/^}/
/// Reads the [args] and does the command.
void main(List<String> args) {
  final parser = ArgParser();
  //M1
  parser.addOption(
    'file',
    abbr: 'f',
    help: 'A file inspected for the key and the version',
  );
  //M1
  parser.addOption(
    'key',
    abbr: 'k',
    help: 'The passphrase for encoding/decoding',
  );
  //M1
  parser.addOption(
    'version',
    abbr: 'V',
    help: 'Defines the cipher algorithm: 1 or 2',
    allowed: ['1', '2', '3'],
  );
  //M1
  parser.addFlag(
    'verbose',
    abbr: 'v',
    help: 'shows more information',
  );
  //M2
  final encodeParser = ArgParser();
  //M2
  final decodeParser = ArgParser();
  //M3
  parser.addCommand('encode', encodeParser);
  //M3
  parser.addCommand('decode', decodeParser);
  //M4
  decodeParser.addFlag(
    'all-fields',
    abbr: 'a',
    help: 'All ciphered entries of the file will be shown.',
  );
  //M4
  encodeParser.addFlag(
    'shortest',
    abbr: 's',
    help:
        'Ciphers to the smallest possible value. Otherwise additional characters will be added to the result.',
  );
  //M5
  final results = parser.parse(args);
  //M6
  if (results.command == null) {
    error('missing <command>');
  }
  //M7
  Storage? storage;
  //M7
  final filename = results['file'];
  //M8
  if (filename != null) {
    storage = Storage(filename as String);
    storage.read();
    if (storage.asInt(Storage.keyVersion) == null) {
      usage('not a storage file: $filename', parser);
    }
  }
  //M9
  storage ??= Storage('');
  //M9
  final mode = results.command!.name!;
  //M10
  if (results['key'] != null) {
    storage.dataSafe!.cipher.setSecret(results['key'] as String);
  }
  //M11
  if ('encode'.startsWith(mode)) {
    cipher(storage, results.command!, parser);
  } else if ('decode'.startsWith(mode)) {
    decipher(storage, results.command!, parser);
  } else {
    usage('unknown mode: $mode', parser);
  }
}

//F/^}/
/// Ciphers the [arguments] with the given [options] using the [storage].
void cipher(Storage storage, ArgResults results, ArgParser parser) {
  if (results.rest.isEmpty) {
    usage('missing <data>', parser);
  }
  for (final arg in results.rest) {
    var data = storage.dataSafe!.cipher.cipher(arg);
    if (!(results['shortest'] as bool)) {
      data = storage.dataSafe!.cipher
          .extendHex(data, DateTime.now().microsecond * 13);
    }
    log(data);
  }
}

//F/^}/
/// Deciphers the [arguments] with the given [options] using the [storage].
void decipher(Storage storage, ArgResults results, ArgParser parser) {
  if (results['all-fields'] as bool) {
    for (final key in storage.variables.keys) {
      final value = storage.asString(key);
      if (value != null && value.startsWith(Storage.passwordMarker)) {
        log('[$key]: ${storage.asPassword(key)}');
      }
    }
  } else if (results.rest.isEmpty) {
    usage('missing <data>', parser);
  } else {
    for (final arg in results.rest) {
      final data = storage.dataSafe!.cipher.decipher(arg);
      log(data ?? '');
    }
  }
}

//F/^}/
void usage(String message, ArgParser parser) {
  log('''
Usage: guard_cli <command> <args_and_opts>'
  Ciphers/deciphers data''');
  log(parser.usage);
  log('''
guard_cli decode <opts> <data1> [<data2> ...]
  Deciphers <dataN>.''');
  log(parser.commands['encode']!.usage);
  log('''
guard_cli encode <data1> [<data2> ...]
  Deciphers <dataN>.''');
  log(parser.commands['decode']!.usage);
  error(message);
  exit(1);
}

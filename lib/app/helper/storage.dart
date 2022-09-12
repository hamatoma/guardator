import 'dart:io';

import 'cipher.dart';
import 'data_safe_custom.dart';
import 'string_tools.dart';

typedef ErrorFunction = Function(String message);

class Storage {
  static final isLinux = Platform.isLinux;
  static final isWindows = Platform.isWindows;
  static final separator = Platform.pathSeparator;
  static const passwordMarker = '!';
  static const keyPassword = 'storage.password';
  static const keyVersion = 'storage.version';
  final String filename;
  final variables = <String, String>{};
  bool comesFromFile = false;
  late final DataSafe? dataSafe;

  Storage(this.filename, {DataSafe? dataSafe}) {
    if (dataSafe == null) {
      DataSafeCustom.checkPreconditions();
    }
    this.dataSafe = dataSafe ?? DataSafeCustom();
  }

  /// Returns the value of a [key] from the internal [variables] as integer.
  ///
  /// If the key does not exist ot the value is not an integer
  /// the [defaultValue] is returned.
  int? asInt(String key, {int? defaultValue}) {
    final value = asString(key);
    final rc =
        value == null ? defaultValue : int.tryParse(value) ?? defaultValue;
    return rc;
  }

  /// Returns a variable with a given [key] and decode that.
  String? asPassword(String key) {
    String? rc = asString(key);
    if (rc != null) {
      if (!rc.startsWith(Storage.passwordMarker)) {
        error('$key not marked');
        rc = null;
      } else {
        try {
          final raw = dataSafe!.cipher.cleanHex(rc.substring(1));
          rc = dataSafe!.cipher.decipher(raw);
        } on FormatException {
          error('invalid encryption: $key');
          rc = null;
        }
      }
    }
    return rc;
  }

  /// Returns the value of a [key] from the internal [variables] as string.
  ///
  /// If the key does not exist the [defaultValue] is returned.
  bool? asBool(String key, {bool? defaultValue}) {
    var rc = defaultValue;
    var value = asString(key);
    if (value != null) {
      value = value.toLowerCase();
      rc = ['true', 'yes', 'on', '1'].contains(value);
      if (rc && ['false', 'no', 'off', '0'].contains(value)) {
        error('not a boolean ($key): $value');
      }
    }
    return rc;
  }

  /// If the key does not exist the [defaultValue] is returned.
  String? asString(String key, {String? defaultValue}) {
    final rc = variables.containsKey(key) ? variables[key] : defaultValue;
    return rc;
  }

  /// Tests the validity of a [password] from the variable named [key].
  ///
  /// Returns true if the password is correct.
  bool checkPassword({required String password, required String key}) {
    final current = asPassword(key);
    final rc = current != null && password == current;
    return rc;
  }

  bool read({String? filename, ErrorFunction? onError}) {
    bool rc = true;
    filename ??= this.filename;
    final file = File(filename);
    final regExp = RegExp(r'^([\w.-]+)\s*=\s*(.*)');
    variables.clear();
    try {
      final lines = file.readAsLinesSync();
      for (final line in lines) {
        final matcher = regExp.firstMatch(line);
        if (matcher != null) {
          final key = matcher.group(1)!;
          variables[key] = matcher.group(2)!;
        }
      }
      //@ToDo: comesFromFile
      comesFromFile = asInt(keyVersion) != null;
    } on Exception catch (exc, stack) {
      error('$exc: $stack');
      if (onError != null) {
        onError('$exc');
      }
      rc = false;
    }
    return rc;
  }

  /// Sets a variable with [key] to the encrypted [value].
  void setAsPassword({required String key, required String value}) {
    variables[key] = Storage.passwordMarker +
        dataSafe!.cipher.extendHex(
            dataSafe!.cipher.cipher(value), DateTime.now().millisecond);
  }

  /// Writes the [variables] to a file named [filename].
  ///
  /// [onError] is called on errors.
  bool write({String? filename, ErrorFunction? onError}) {
    bool rc = true;
    filename ??= this.filename;
    final file = File(filename);
    final lines = <String>[];
    final keys = variables.keys.toList();
    keys.sort();
    for (final key in keys) {
      lines.add('$key=${variables[key]!}\n');
    }
    try {
      file.writeAsStringSync(lines.join());
    } on Exception catch (exc, stack) {
      error('$exc: $stack');
      if (onError != null) {
        onError('$exc');
      }
      rc = false;
    }
    return rc;
  }

  static String buildFilename({required String application, String? variant}) {
    final path =
        isWindows ? 'c:\\programs\\guardator\\config\\' : '/etc/guardator/';
    final rc = variant == null
        ? '$path$application.conf'
        : '$path$application.$variant.conf';
    return rc;
  }
}

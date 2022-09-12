import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:path/path.dart' as m_path;

import 'package:guardator/app/helper/data_safe_custom.dart';
import 'package:guardator/app/helper/storage.dart';

void main() {
  const code = 'TopSecret';
  final filenames = init(code);
  final filename = filenames[0];
  final filenameV2 = filenames[1];
  final storage = Storage(filename);
  final storageV2 = Storage(filenameV2);
  storage.read();
  storageV2.read();
  group('read/write', () {
    test('string', () {
      expect(storage.asString(keyString), 'Good');
    });
    test('int', () {
      expect(storage.asInt(keyInt), 4711);
    });
    test('bool', () {
      expect(storage.asBool(keyBoolTrue), isTrue);
      expect(storage.asBool(keyBoolFalse), isFalse);
      expect(storageV2.asBool(keyBoolTrue), isTrue);
      expect(storageV2.asBool(keyBoolFalse), isFalse);
    });
    test('password', () {
      expect(storage.asPassword(Storage.keyPassword), code);
    });
    test('write', () {
      final filename2 = filename.replaceFirst('storage', 'storage2');

      storage.write(filename: filename2);
      final storage2 = Storage(filename2);
      storage2.read();
      expect(storage2.asString(keyString), 'Good');
      expect(storage2.asInt(keyInt), 4711);
      expect(storage2.asPassword(Storage.keyPassword), code);
      expect(storage2.checkPassword(password: code, key: Storage.keyPassword),
          isTrue);
    });
  });
  group('Errors', () {
    test('not password', () {
      expect(storage.asPassword(keyString), isNull);
      expect(storageV2.asPassword(keyString), isNull);
    });
    test('Wrong encoding', () {
      expect(storage.asPassword(Storage.keyPassword), isNotNull);
      final oldKey = storage.dataSafe!.cipher.secret;
      storage.dataSafe!.cipher.setSecret('Wow');
      expect(storage.asPassword(Storage.keyPassword), isNull);
      storage.dataSafe!.cipher.setSecret(oldKey);
    });
  });
  group('Errors', () {
    test('not password', () {
      expect(storage.asPassword(keyString), isNull);
      expect(storageV2.asPassword(keyString), isNull);
    });
    test('Wrong encoding', () {
      //expect(storage.asPassword(Storage.keyPassword), isNotNull);
      final oldKey = storage.dataSafe!.cipher.secret;
      storage.dataSafe!.cipher.setSecret('Wow');
      expect(storage.asPassword(Storage.keyPassword), isNull);
      storage.dataSafe!.cipher.setSecret(oldKey);
    });
  });
}

const keyBoolFalse = 'ignore';
const keyBoolTrue = 'automatic';
const keyInt = 'ignore.case';
const keyString = 'test.text';

List<String> init(String code) {
  final filename = m_path.join(Directory.systemTemp.path, 'cunit/storage.conf');
  final parent = Directory(m_path.dirname(filename));
  if (!parent.existsSync()) {
    parent.createSync(recursive: true);
  }
  if (!DataSafeCustom.checkPreconditions(throwOnError: false)) {
    DataSafeCustom.initFromScratch(secret0: DataSafeCustom.defaultSecret0(),
        secret1: DataSafeCustom.defaultSecret1());
  }
  final file = File(filename);
  file.writeAsStringSync('''# Test configuration
$keyString = Good
$keyBoolTrue = True
$keyBoolFalse = False
$keyInt = 4711
''');
  final storage = Storage(filename);
  storage.read();
  storage.setAsPassword(key: Storage.keyPassword, value: code);
  storage.write();

  final filenameV2 =
      m_path.join(Directory.systemTemp.path, 'cunit/storage.v2.conf');
  final parentV2 = Directory(m_path.dirname(filename));
  if (!parentV2.existsSync()) {
    parentV2.createSync(recursive: true);
  }
  final fileV2 = File(filenameV2);
  fileV2.writeAsStringSync('''# Test configuration
${Storage.keyVersion}=1
$keyString = Good
$keyBoolTrue = Yes
$keyBoolFalse = No
''');
  final storage2 = Storage(filenameV2);
  storage2.read();
  storage2.setAsPassword(key: Storage.keyPassword, value: code);
  storage2.write();

  final filenameV3 =
      m_path.join(Directory.systemTemp.path, 'cunit/storage.v3.conf');
  final parentV3 = Directory(m_path.dirname(filename));
  if (!parentV3.existsSync()) {
    parentV3.createSync(recursive: true);
  }
  final fileV3 = File(filenameV3);
  fileV3.writeAsStringSync('''# Test configuration
${Storage.keyVersion}=1
$keyString = Good
$keyBoolTrue = Yes
$keyBoolFalse = No
$keyInt=4711
''');
  final storage3 = Storage(filenameV3);
  storage3.read();
  storage3.setAsPassword(key: Storage.keyPassword, value: code);
  storage3.write();
  return [filename, filenameV2, filenameV3];
}

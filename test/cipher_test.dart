import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';

import 'package:guardator/app/helper/cipher.dart';

void main() {
  final cipher = Cipher(version: 1);
  final cipherV2 = Cipher(version: 2);
  final cipherV3 = Cipher(version: 3);
  group('Basic en/decoding', () {
    test('cleanHex', () {
      expect(
          cipher.cleanHex(
              r'^1234567890!"§$%&/()=?qwertzuiopQWERTZUIOPasdfghjklASDFGHJKLyxcvbnm,.'),
          'qwertzuiasdfghjk');
    });
    test('extendHex', () {
      expect(cipher.extendHex('qwertzuiasdfghjk', 738292821),
          '/VqZ/wU(eI)rO=tP?zAouSpiDlaFysGxdHcfJvgKbhLnjYmkX-');
      expect(cipher.cleanHex('/GqZ/wUeIrOtP?zAuSiDaFysGdHfJgKbhLjYkX'),
          'qwertzuiasdfghjk');
    });
    test('hexToBytes', () {
      expect(cipher.hexToBytes('qwertzasdf'), [1, 35, 69, 137, 171]);
      expect(cipher.hexToBytes('qwertzuiasdfghjkkk'),
          [1, 35, 69, 103, 137, 171, 205, 239, 255]);
    });
    test('bytesToHex', () {
      expect(cipher.bytesToHex(Uint8List.fromList([1, 35, 69, 137, 171])),
          'qwertzasdf');
      expect(cipher.bytesToHex(Uint8List.fromList([1, 9, 254, 255, 64])),
          'qwqskjkktq');
      expect(
          cipher.bytesToHex(
              Uint8List.fromList([1, 35, 69, 103, 137, 171, 205, 239, 255])),
          'qwertzuiasdfghjkkk');
    });
  });
  group('Encoding V1', () {
    test('hexToBytes', () {
      expect(cipher.hexToBytes('qwertzasdf'), [1, 35, 69, 137, 171]);
    });
    test('bytesToHex', () {
      expect(cipher.bytesToHex(Uint8List.fromList([1, 35, 69, 137, 171])),
          'qwertzasdf');
      expect(cipher.bytesToHex(Uint8List.fromList([1, 9, 254, 255, 64])),
          'qwqskjkktq');
    });

    test('encode', () {
      expect(cipher.cipher('abc'), 'kakskd');
      expect(cipher.cipher(r'34891fjaö302ß1<-FDSAFJKW$§;'),
          'gdgfgkhqgakhqwkazdthgdgigszdrugahrgthhhfjdhahhjwjejjffzsrjhe');
    });
    test('decode', () {
      expect(cipher.decipher('kakskd'), 'abc');
      expect(
          cipher.decipher(
              'gdgfgkhqgakhqwkazdthgdgigszdrugahrgthhhfjdhahhjwjejjffzsrjhe'),
          r'34891fjaö302ß1<-FDSAFJKW$§;');
    });
  });
  group('Encoding V2', () {
    test('encode/decode V2', () {
      var encoded = cipherV2.cipher('j');
      expect(encoded.length, 4 + 2);
      var current = cipherV2.decipher(encoded);
      expect(current, 'j');
      encoded = cipherV2.cipher('A good test?!');
      expect(encoded.length, 4 + 13 * 2);
      current = cipherV2.decipher(encoded);
      expect(current, 'A good test?!');
    });
  });
  group('Errors', () {
    test('Wrong encoding', () {
      final cipher = Cipher(secret: 'abc', version: 1);
      final encoded = cipher.cipher('123');
      cipher.setSecret('!fjdkallk1');
      expect(cipher.decipher(encoded) != 'abc', isTrue);
    });
    test('Wrong encoding V2', () {
      final cipher = Cipher(secret: 'abc', version: 2);
      final encoded = cipher.cipher('123');
      cipher.setSecret('!secretjfda');
      expect(cipher.decipher(encoded) != '123', isTrue);
    });
    test('Wrong encoding V3', () {
      final cipher = Cipher(secret: 'abc', version: 3);
      final encoded = cipher.cipher('123');
      cipher.setSecret('!secret');
      expect(cipher.decipher(encoded), isNull);
    });
  });
  group('Encoding V3', () {
    test('encode/decode V3', () {
      var encoded = cipherV3.cipher('j');
      expect(encoded.length, 4 + 32);
      var current = cipherV3.decipher(encoded);
      expect(current, 'j');
      encoded = cipherV3.cipher('A good test?!');
      expect(encoded.length, 4 + 32);
      current = cipherV3.decipher(encoded);
      expect(current, 'A good test?!');
    });
  });
  group('AES', () {
    test('encode/decode AES', () {
      var secret = 'TopSecret!jfldyif905490kfdlaflödsakfopüif901i901';
      var salt = 'u8942qjcy<jvoipu4892jl-damflö<ujr89jfdkafkl-<mfläa';
      var encoded = cipherV3.encodeAES(data: 'j', secret: secret, salt: salt);
      expect(
          cipherV3.decodeAES(data: encoded, secret: secret, salt: salt), 'j');
      secret = 'x';
      salt = 'y';
      encoded = cipherV3.encodeAES(
          data: 'Be or not to be, that is the question!',
          secret: secret,
          salt: salt);
      expect(cipherV3.decodeAES(data: encoded, secret: secret, salt: salt),
          'Be or not to be, that is the question!');
    });
  });
  group('DataSafe', () {
    test('basic', () {
      final safe = DataSafe.fromLength(300, cipher);
      var secret = 'hello';
      safe.storeSecret(safe.indexMask2 + 1, secret);
      expect(safe.readSecret(safe.indexMask2 + 1), secret);
      secret = 'öäüÖÄÜß§ With a little help from my friends.';
      safe.storeSecret(219, secret);
      expect(safe.readSecret(219), secret);
    });
    test('int16', () {
      final safe = DataSafe.fromLength(300, cipher);
      var masks1 = [0xC4];
      var masks2 = [0x12, 0x44];
      expect(safe.storeInt16(offset: 3, value: 47, masks: masks2), isTrue);
      expect(safe.readInt16(offset: 3, masks: masks2), 47);
      expect(safe.storeInt16(offset: 34, value: 65535), isTrue);
      expect(safe.readInt16(offset: 34), 65535);
      expect(safe.storeInt16(offset: 123, value: 32000, masks: masks1), isTrue);
      expect(safe.readInt16(offset: 123, masks: masks1), 32000);
    });
    test('error-int16-offset-to-high', () {
      final safe = DataSafe.fromLength(300, cipher);
      expect(safe.storeInt16(offset: 299, value: 47), isFalse);
      expect(safe.readInt16(offset: 299), -1);
    });
    test('error-int16-value-to-high', () {
      final safe = DataSafe.fromLength(300, cipher);
      expect(safe.storeInt16(offset: 299, value: 70000), isFalse);
    });
    test('frequency', () {
      final safe = DataSafe.fromLength(0x10000, cipher);
      safe.fill();
      safe.showFrequency(10);
    });
    test('error-readSecret-offset-too-large', () {
      final safe = DataSafe.fromLength(24, cipher);
      var secret = 'hello';
      expect(safe.storeSecret(4, secret), isTrue);
      expect(safe.readSecret(4), secret);
      expect(safe.storeSecret(5, secret), isFalse);
      expect(safe.readSecret(5), isNull);
    });
  });
}

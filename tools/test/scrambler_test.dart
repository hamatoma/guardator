import 'dart:io';

import 'package:path/path.dart' as m_path;
import 'package:test/test.dart';

import '../bin/cipher.dart';
import '../bin/cipher_io.dart';
import '../bin/data_safe_custom.dart';
import '../bin/scrambler.dart' as m_scrambler;

void main() {
  final filenames = init();
  final filename1 = filenames[0];
  final filename2 = filenames[1];
  final filenameOut = filename1.replaceAll('.dart', '.out');
  m_scrambler.underTest = true;
  group('codepoints', () {
    test('basic', () {
      m_scrambler.main(['codepoints', 'abcd', '1234']);
      expect(m_scrambler.lastResultLines, ['[97,98,99,100]', '[49,50,51,52]']);
    });
    test('option masks', () {
      m_scrambler.main(['codepoints', '--masks=123,255', 'abcd', '1234']);
      expect(
        m_scrambler.lastResultLines,
        ['[26,157,24,155]', '[74,205,72,203]'],
      );
      expect(
        fromCodepoints(data: [26, 157, 24, 155], masks: [123, 255]),
        'abcd',
      );
    });
  });
  group('errors-codepoints', () {
    test('wrong masks: not an integer', () {
      m_scrambler.main(['codepoints', '--masks=3x', '1234']);
      expect(m_scrambler.lastResultLines, ['ERROR']);
    });
  });
  group('shuffle', () {
    test('basic', () {
      m_scrambler.main(['shuffle', '--reverse', filename1, filenameOut]);
      final lines = File(filenameOut).readAsLinesSync();
      expect(lines.join('\n'), reversedData1);
    });
  });
  group('shuffler', () {
    test('basic', () {
      final shuffler = m_scrambler.Shuffler(File(filename1));
      expect(shuffler.buildFileBlocks(), isTrue);
      shuffler.mix(m_scrambler.reverseRangeBuilder);
      final lines = shuffler.join();
      expect(lines.join('\n'), reversedData1);
    });
  });
  group('create-safe', () {
    final output = m_path.join(Directory.systemTemp.path, 'cunit', 'safe.data');
    test('basic', () {
      m_scrambler.main([
        'create-safe',
        '--secret=abc',
        '--size=512',
        output,
        '132',
        'TopSecret'
      ]);
      expect(m_scrambler.lastResultLines.join('\n'), 'OK');
    });
  });
  group('patch-safe', () {
    final output = m_path.join(Directory.systemTemp.path, 'cunit', 'safe.data');
    test('basic', () {
      expect(m_scrambler.lastResultLines.join('\n'), 'OK');
      m_scrambler.main([
        'patch-safe',
        '--secret=abc',
        filename2,
        output,
        '132',
        'TopSecret'
      ]);
      final safe = DataSafeCustom.fromFile(filename: filename2);
      expect(safe.data.length, 1024);
    });
  });
  group('store-int16', () {
    test('basic', () {
      m_scrambler
          .main(['store-int16', '--masks=123,0x44', filename2, '132', '0x777']);
      expect(m_scrambler.lastResultLines.join('\n'), 'OK');
    });
  });
  group('initialize', () {
    test('basic', () {
      final file =
          m_path.join(Directory.systemTemp.path, 'cunit', 'datasafe.test');
      m_scrambler.main([
        'initialize',
        '--file=$file',
        '--secret=TopSecret',
        '--secret2=NobodyKnows',
        '--size=8192',
        '--force'
      ]);
      expect(m_scrambler.lastResultLines.join('\n'), 'OK');
    });
  });
  group('errors-shuffle', () {
    test('wrong command', () {
      m_scrambler.main(['shuffler', filename1, filenameOut]);
      expect(m_scrambler.lastResultLines.join('\n'), 'missing <command>');
    });
    test('wrong option', () {
      m_scrambler.main(['shuffle', '--unknown=abc']);
      expect(
        m_scrambler.lastResultLines.join('\n'),
        'FormatException: Could not find an option named "unknown".',
      );
    });
    test('missing output', () {
      m_scrambler.main(['shuffle', filename1]);
      expect(m_scrambler.lastResultLines.join('\n'), 'missing <output>');
    });
    test('wrong path of output', () {
      m_scrambler.main(['shuffle', filename1]);
      expect(m_scrambler.lastResultLines.join('\n'), 'missing <output>');
    });
  });
  group('errors-basic', () {
    test('wrong command', () {
      m_scrambler.main(['shuffler', filename1, filenameOut]);
      expect(m_scrambler.lastResultLines.join('\n'), 'missing <command>');
    });
    test('wrong option', () {
      m_scrambler.main(['shuffle', '--unknown=abc']);
      expect(
        m_scrambler.lastResultLines.join('\n'),
        'FormatException: Could not find an option named "unknown".',
      );
    });
  });
  group('errors-shuffle', () {
    test('missing output', () {
      m_scrambler.main(['shuffle', filename1]);
      expect(m_scrambler.lastResultLines.join('\n'), 'missing <output>');
    });
    test('wrong path of output', () {
      m_scrambler.main(['shuffle', filename1, '/tmp/not.exists/blabla']);
      expect(m_scrambler.lastResultLines.join('\n'), 'ERROR');
    });
    test('wrong path of input', () {
      m_scrambler
          .main(['shuffle', '/tmp/not.exists/$filename1', '/tmp/blabla']);
      expect(m_scrambler.lastResultLines.join('\n'), 'ERROR');
    });
  });
  group('errors-create-safe', () {
    test('missing output', () {
      m_scrambler.main(['create-safe']);
      expect(m_scrambler.lastResultLines.join('\n'), 'ERROR');
    });
    test('wrong path of output', () {
      m_scrambler.main(['create-safe', '/tmp/not.exists/blabla']);
      expect(m_scrambler.lastResultLines.join('\n'), 'ERROR');
    });
    test('not an int (offset)', () {
      final output =
          m_path.join(Directory.systemTemp.path, 'cunit', 'safe.data');
      m_scrambler.main(['create-safe', output, '2x', 'secret']);
      expect(m_scrambler.lastResultLines.join('\n'), 'ERROR');
    });
  });
  group('errors-patch-safe', () {
    test('missing file', () {
      m_scrambler.main(['patch-safe']);
      expect(m_scrambler.lastResultLines.join('\n'), 'ERROR');
    });
    test('wrong path of file', () {
      m_scrambler.main(['patch-safe', '/tmp/not.exists/blabla']);
      expect(m_scrambler.lastResultLines.join('\n'), 'ERROR');
    });
    test('not an int (offset)', () {
      final output =
          m_path.join(Directory.systemTemp.path, 'cunit', 'safe.data');
      m_scrambler.main(['patch-safe', output, '2x', 'secret']);
      expect(m_scrambler.lastResultLines.join('\n'), 'ERROR');
    });
  });
}

const reversedData1 = '''
import "dart:io";

//F/^}/
void main(List<String> args){
  exit(1);
}
//F/;/
String name = 'abc';
//F/;/
int version = 1;

//F/^}/
class B{
}
//F/^}/
class A{
  //M1
  int _y;
  //M1
  String _x;
  //M10
  A(this.x, this.y);
  //M10.1
  int get y => _y;
  //M10.1
  int get x => _x;
  //MEnd
}''';

List<String> init() {
  m_scrambler.underTest = true;
  if (!Directory(DataSafeCustom.defaultFilename()).existsSync()) {
    DataSafeCustom.initFromScratch(
      secret0: DataSafeCustom.defaultSecret0(),
      secret1: DataSafeCustom.defaultSecret1(),
    );
  }
  final parent = Directory(m_path.join(Directory.systemTemp.path, 'cunit'));
  if (!parent.existsSync()) {
    parent.createSync(recursive: true);
  }
  final file1 = File(m_path.join(parent.path, 'scramble1.dart'));
  final file2 = File(m_path.join(parent.path, 'safe1.data'));
  if (!file2.existsSync()) {
    DataSafeIO.fromLength(1024, Cipher()).write(file2.path);
  }
  file1.writeAsStringSync('''
import "dart:io";
//F/^}/
class A{
  //M1
  String _x;
  //M1
  int _y;
  //M10
  A(this.x, this.y);
  //M10.1
  int get x => _x;
  //M10.1
  int get y => _y;
  //MEnd
}

//F/^}/
class B{
}
//F/;/
int version = 1;
//F/;/
String name = 'abc';

//F/^}/
void main(List<String> args){
  exit(1);
}
''');
  return [file1.path, file2.path];
}

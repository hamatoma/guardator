import 'package:get/get.dart';

import '../../../helper/storage.dart';

class StorageController extends GetxController {
  static const application = 'thunderbird';
  static const variant = 'hm';
  final needOldPassword = true.obs;
  Storage? storage;
  bool isValid(String password) =>
      storage!.checkPassword(password: password, key: 'code.secret');

  @override
  void onInit() {
    storage = Storage(
        Storage.buildFilename(application: application, variant: variant));
    needOldPassword.value = storage!.asInt(Storage.keyVersion) != null;
    storage!.read();
    super.onInit();
  }

  void error(String message) {
    // do nothing?
  }

  /// Changes the password to a given [value].
  void changePassword(String value) {
    storage!.setAsPassword(key: Storage.keyPassword, value: value);
    storage!.write(onError: (_) => error(_));
    storage!.read(onError: (_) => error(_));
    needOldPassword.value = storage!.asString(Storage.keyPassword) != null;
  }
}

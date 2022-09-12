import 'package:flutter/cupertino.dart';

import 'package:get/get.dart';

import '../../../helper/storage.dart';
import '../../home/controllers/storage_controller.dart';

class SettingsController extends GetxController {
  var storage = Storage('dummy');
  final showPassword = false.obs;
  final neededError = ''.obs;
  final repetitionError = ''.obs;
  final statusMessage = ''.obs;
  final oldPasswordController = TextEditingController();
  final newPasswordController = TextEditingController();
  final repetitionController = TextEditingController();
  final StorageController storageController = Get.find();

  void error(String message) {
    status('+++ $message');
  }

  void init({required String application, String? variant}) {
    storage = Storage(
        Storage.buildFilename(application: application, variant: variant));
    storage.read();
  }

  @override
  void onInit() {
    init(application: 'guardator', variant: 'hm');
    super.onInit();
  }

  void status(String message) {
    statusMessage.value = message;
  }

  void storePassword() {
    storageController.changePassword(newPasswordController.text);
    status('Settings are saved');
    oldPasswordController.text = '';
    newPasswordController.text = '';
    repetitionController.text = '';
    update();
  }
}

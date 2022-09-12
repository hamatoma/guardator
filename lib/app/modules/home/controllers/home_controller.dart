import 'dart:io';

import 'package:flutter/material.dart';

import 'package:get/get.dart';

import 'package:guardator/app/modules/home/controllers/storage_controller.dart';

import '../../../helper/storage.dart';

class HomeController extends GetxController {
  final password = ''.obs;
  final showPassword = false.obs;
  final statusMessage = ''.obs;
  final passwordController = TextEditingController();
  final countErrors = 0.obs;
  final StorageController storageController = Get.put(StorageController());

  void status(String message) {
    statusMessage.value = message;
  }

  /// Returns whether a given [password] is correct.
  bool isValid() {
    final rc = storageController.storage!.checkPassword(
        password: passwordController.text, key: Storage.keyPassword);
    if (!rc) {
      if (++countErrors.value >= 7) {
        exit(0);
      }
    }
    return rc;
  }

  int run() {
    final executable = storageController.storage!.asString('executable');
    final argumentsAsString = storageController.storage!.asString('arguments');
    final arguments = argumentsAsString == null || argumentsAsString.isEmpty
        ? <String>[]
        : argumentsAsString.split(',');
    final runInShell =
        storageController.storage!.asBool('run.in.shell', defaultValue: false);
    var rc = 100;
    if (executable != null) {
      Process.run(executable, arguments, runInShell: runInShell!)
          .then((process) => exit(process.exitCode));
    }
    return rc;
  }
}

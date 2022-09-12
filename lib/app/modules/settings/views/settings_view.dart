import 'package:flutter/material.dart';

import 'package:get/get.dart';

import '../../../helper/storage.dart';
import '../../../routes/app_pages.dart';
import '../controllers/settings_controller.dart';

class SettingsView extends GetView<SettingsController> {
  static const padding = 16.0;
  const SettingsView({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Scaffold(
        appBar: AppBar(
          title: const Text('SettingsView'),
          centerTitle: true,
        ),
        body: Form(
            child:
                Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Obx(() => Visibility(
              visible: controller.storageController.needOldPassword.value,
              child: Obx(() => TextFormField(
                    controller: controller.oldPasswordController,
                    obscureText: !controller.showPassword.value,
                    decoration:
                        const InputDecoration(labelText: 'Old password'),
                  )))),
          const SizedBox(height: padding),
          Obx(() => TextFormField(
                controller: controller.newPasswordController,
                obscureText: !controller.showPassword.value,
                decoration: const InputDecoration(labelText: 'New password'),
              )),
          const SizedBox(height: padding),
          Obx(() => TextFormField(
                controller: controller.repetitionController,
                obscureText: !controller.showPassword.value,
                decoration: const InputDecoration(labelText: 'Repetition'),
              )),
          const SizedBox(height: padding),
          rowButton(),
          const SizedBox(height: padding),
          Obx(
            () => Text(controller.statusMessage.value,
                style: TextStyle(
                    color: controller.statusMessage.value.startsWith('+++')
                        ? Colors.red
                        : Colors.blue)),
          ),
        ])));
  }

  bool check() {
    var rc = true;
    final check = controller.storageController.needOldPassword.value;
    if (check &&
        !controller.storage.checkPassword(
            password: controller.oldPasswordController.text,
            key: Storage.keyPassword)) {
      controller.status(controller.neededError.value = 'Wrong old password');
      rc = false;
    }
    if (rc && controller.newPasswordController.text.isEmpty) {
      controller.status('+++ missing password');
      rc = false;
    }
    if (rc &&
        controller.newPasswordController.text !=
            controller.repetitionController.text) {
      controller
          .status(controller.neededError.value = 'Passwords are not equal');
      rc = false;
    }
    if (rc) {
      controller.status('Settings saved');
    }
    return rc;
  }

  Widget rowButton() {
    final rc = Row(
      children: [
        ElevatedButton(
          onPressed: () {
            save();
          },
          child: const Text('Save'),
        ),
        const Expanded(
          child: SizedBox(width: 1),
        ),
        Obx(() => Checkbox(
            value: controller.showPassword.value,
            onChanged: (_) {
              controller.showPassword.value =
                  _ ?? !controller.showPassword.value;
            })),
        const SizedBox(width: padding / 2),
        const Text('Show password', textAlign: TextAlign.center),
        const Expanded(child: SizedBox(width: 1)),
        ElevatedButton(
          onPressed: () => Get.toNamed(Routes.routeHome),
          child: const Text('Login'),
        ),
      ],
    );
    return rc;
  }

  void save() {
    if (check()) {
      controller.storePassword();
    }
  }
}

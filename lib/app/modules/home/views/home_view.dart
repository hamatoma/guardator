import 'package:flutter/material.dart';

import 'package:get/get.dart';

import '../../../routes/app_pages.dart';
import '../controllers/home_controller.dart';

class HomeView extends GetView<HomeController> {
  static const padding = 16.0;
  const HomeView({Key? key}) : super(key: key);
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('HomeView'),
        centerTitle: true,
      ),
      body: Form(
          child:
              Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Obx(() => TextFormField(
              controller: controller.passwordController,
              obscureText: !controller.showPassword.value,
              decoration: const InputDecoration(labelText: 'Passwort'),
            )),
        const SizedBox(height: padding),
        rowButton(),
        const SizedBox(height: padding),
        Obx(() => Text(controller.statusMessage.value,
            style: TextStyle(
                color: controller.statusMessage.value.startsWith('+++')
                    ? Colors.red
                    : Colors.blue))),
      ])),
    );
  }

  void login() {
    if (controller.isValid()) {
      controller.run();
    } else {
      controller.status('+++ invalid password');
    }
  }

  Widget rowButton() {
    final rc = Row(children: [
      ElevatedButton(
        onPressed: () => login(),
        child: const Text('Login'),
      ),
      const Expanded(child: SizedBox(width: 1)),
      Obx(() => Checkbox(
          value: controller.showPassword.value,
          onChanged: (_) {
            controller.showPassword.value = _ ?? !controller.showPassword.value;
          })),
      const SizedBox(width: padding / 2),
      const Text('Show password', textAlign: TextAlign.center),
      const Expanded(child: SizedBox(width: 1)),
      ElevatedButton(
        onPressed: () => Get.toNamed(Routes.routeSettings),
        child: const Text('Settings'),
      ),
    ]);
    return rc;
  }
}

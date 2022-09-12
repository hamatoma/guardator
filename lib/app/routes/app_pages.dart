import 'package:get/get.dart';

import '../modules/home/bindings/home_binding.dart';
import '../modules/home/views/home_view.dart';
import '../modules/settings/bindings/settings_binding.dart';
import '../modules/settings/views/settings_view.dart';

part 'app_routes.dart';

class AppPages {
  AppPages._();

  static const initialPage = Routes.routeHome;

  static final routes = [
    GetPage(
      name: _Paths.pathHome,
      page: () => const HomeView(),
      binding: HomeBinding(),
    ),
    GetPage(
      name: _Paths.pathSettings,
      page: () => const SettingsView(),
      binding: SettingsBinding(),
    ),
  ];
}

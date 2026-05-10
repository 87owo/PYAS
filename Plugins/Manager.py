import importlib
import os
import sys

def load_custom_plugins(plugin_directory):
    # Belirtilen dizindeki tüm Python eklentilerini dinamik olarak yükler
    loaded_plugins = []

    if not os.path.exists(plugin_directory):
        os.makedirs(plugin_directory)
        return loaded_plugins

    for filename in os.listdir(plugin_directory):
        if filename.endswith(".py") and filename != "__init__.py":
            module_name = filename[:-3]
            try:
                sys.path.insert(0, plugin_directory)
                module = importlib.import_module(module_name)
                # Eklentinin geçerli bir tarama fonksiyonu var mı kontrol et
                if hasattr(module, 'run_scan'):
                    loaded_plugins.append(module)
            except ImportError as e:
                print(f"Eklenti yüklenemedi ({module_name}): {e}")
            finally:
                sys.path.pop(0)

    return loaded_plugins
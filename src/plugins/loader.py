"""
Plugin Loader - Automatically discovers and loads vulnerability plugins.
Adding new plugins requires no changes to the main application.
"""

import importlib
import pkgutil
import logging
from typing import List, Dict, Type, Optional
from pathlib import Path

from src.plugins.base import PluginBase, PluginMetadata


logger = logging.getLogger(__name__)


class PluginLoader:
    """
    Automatically discovers and loads vulnerability plugins.
    
    Plugins are discovered from:
    1. src/plugins/low/ - Low severity plugins
    2. src/plugins/medium/ - Medium severity plugins
    3. src/plugins/high/ - High severity plugins
    4. src/plugins/intrusive/ - Intrusive plugins (require consent)
    """
    
    PLUGIN_DIRS = ["low", "medium", "high", "intrusive"]
    
    def __init__(self):
        self.plugins: Dict[str, PluginBase] = {}
        self.plugins_by_severity: Dict[str, List[PluginBase]] = {
            "low": [],
            "medium": [],
            "high": [],
            "intrusive": []
        }
    
    def discover_plugins(self) -> int:
        """
        Discover and load all plugins from plugin directories.
        Returns number of plugins loaded.
        """
        logger.info("Discovering vulnerability plugins...")
        
        base_path = Path(__file__).parent
        
        for severity_dir in self.PLUGIN_DIRS:
            dir_path = base_path / severity_dir
            
            if not dir_path.exists():
                logger.debug(f"Plugin directory not found: {dir_path}")
                continue
            
            package_name = f"src.plugins.{severity_dir}"
            
            try:
                package = importlib.import_module(package_name)
                
                for importer, modname, ispkg in pkgutil.iter_modules([str(dir_path)]):
                    if modname.startswith('_'):
                        continue
                    
                    try:
                        module = importlib.import_module(f"{package_name}.{modname}")
                        
                        for attr_name in dir(module):
                            attr = getattr(module, attr_name)
                            
                            if (isinstance(attr, type) and 
                                issubclass(attr, PluginBase) and 
                                attr is not PluginBase):
                                
                                try:
                                    plugin_instance = attr()
                                    meta = plugin_instance.metadata
                                    
                                    if meta.validate():
                                        self.plugins[meta.id] = plugin_instance
                                        
                                        sev = "intrusive" if meta.intrusive else meta.severity_hint.lower()
                                        if sev in self.plugins_by_severity:
                                            self.plugins_by_severity[sev].append(plugin_instance)
                                        
                                        logger.info(f"Loaded plugin: {meta.name} ({meta.id})")
                                    else:
                                        logger.warning(f"Invalid plugin metadata: {modname}")
                                        
                                except Exception as e:
                                    logger.error(f"Error instantiating plugin {attr_name}: {e}")
                                    
                    except Exception as e:
                        logger.error(f"Error loading module {modname}: {e}")
                        
            except Exception as e:
                logger.debug(f"Could not load package {package_name}: {e}")
        
        total = len(self.plugins)
        logger.info(f"Loaded {total} vulnerability plugins")
        return total
    
    def get_plugins_for_scan(self, scan_level: str, 
                             allow_intrusive: bool = False) -> List[PluginBase]:
        """
        Get plugins that should run for given scan level.
        """
        plugins = []
        
        level_map = {
            "low": ["low"],
            "medium": ["low", "medium"],
            "high": ["low", "medium", "high"]
        }
        
        severities = level_map.get(scan_level.lower(), ["low"])
        
        for severity in severities:
            plugins.extend(self.plugins_by_severity.get(severity, []))
        
        if allow_intrusive:
            plugins.extend(self.plugins_by_severity.get("intrusive", []))
        
        return plugins
    
    def get_plugin_by_id(self, plugin_id: str) -> Optional[PluginBase]:
        """Get a specific plugin by ID."""
        return self.plugins.get(plugin_id)
    
    def get_all_plugins(self) -> List[PluginBase]:
        """Get all loaded plugins."""
        return list(self.plugins.values())
    
    def get_plugin_count(self) -> Dict[str, int]:
        """Get count of plugins by severity."""
        return {
            severity: len(plugins) 
            for severity, plugins in self.plugins_by_severity.items()
        }
    
    def reload_plugins(self) -> int:
        """Reload all plugins."""
        self.plugins.clear()
        for key in self.plugins_by_severity:
            self.plugins_by_severity[key] = []
        return self.discover_plugins()

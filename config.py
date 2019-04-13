import io
import os
from typing import Any, Dict, Union, List

import oyaml as yaml


def camelcase_to_underscore(camelcase: str) -> str:
    res = ''
    last_was_upper = True
    for i in range(len(camelcase)):
        if camelcase[i].isupper() and not last_was_upper:
            res += '_' + camelcase[i].lower()
        else:
            res += camelcase[i]
            last_was_upper = False
    return res


class Config:
    def __init__(self, name: List[str], config_: Dict[str, Any]):
        self._name = name
        self._config = config_

    def __getitem__(self, name: str) -> Any:
        return self._config[name]

    def __contains__(self, name: str):
        return name in self._config

    def __str__(self):
        return "Config({})".format(".".join(self._name))

    @classmethod
    def _assign_key(cls, cfg: Dict[str, Union[dict, Any]], key: str, value: Any, self_path: str):
        found_key = None
        found_key_underscore = None
        first_part = key.split('_', 1)[0]
        for cfg_key in cfg.keys():
            cfg_key_underscore = camelcase_to_underscore(cfg_key)
            if cfg_key_underscore.startswith(first_part):
                if key.startswith(cfg_key_underscore):
                    found_key = cfg_key
                    found_key_underscore = cfg_key_underscore
        if found_key is None:
            raise ValueError("Cannot find {} in {}".format(key, self_path))
        if found_key_underscore == key:
            cfg[found_key] = value
        else:
            cls._assign_key(
                cfg[found_key],
                key[len(found_key_underscore)+1:],
                value,
                self_path + '_' + found_key_underscore
            )

    @classmethod
    def load(cls, config_file='config.yaml', env_prefix='api_config_'):
        with open(config_file, 'r') as f:
            config = yaml.load(f, Loader=yaml.SafeLoader)
        for env_key, env_val in os.environ.items():
            lower_key = env_key.lower()
            if lower_key.startswith(env_prefix):
                lower_key = lower_key[len(env_prefix):]

                cls._assign_key(config, lower_key, yaml.load(io.StringIO(env_val)), env_prefix[:-1])
        return Config(["({})".format(config_file)], config)


config = Config.load()

from collections import OrderedDict
from typing import List, Set, Dict, Any

from model.view_field import ViewField, view_field_types
from model.db import LdapSearchEntity
import model


class ViewList:
    def __init__(self, config: dict, **overrides):
        config.update(overrides)
        self.fields: List[ViewField] = [
            view_field_types[cfg['type']](key, cfg, writable=False)
            for key, cfg in config.items()
        ]

        self.config = [field.config for field in self.fields]

    def init(self, all_views: Dict[str, 'model.view.View']):
        all_fields = {
            field.key: field
            for field in self.fields
        }
        for field in self.fields:
            field.init(all_views, all_fields)

    def get_fetch(self, fetches: Set[str]):
        for field in self.fields:
            field.get_fetch(fetches)

    def get(self, fetches: List[LdapSearchEntity]) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = list()
        for entity in fetches:
            res: Dict[str, Any] = OrderedDict()
            for field in self.fields:
                field.get(entity, res)
            results.append(res)
        return results

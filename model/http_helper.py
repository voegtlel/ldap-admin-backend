from falcon import HTTPBadRequest


class HTTPBadRequestField(HTTPBadRequest):
    """400 Bad Request. With extensions to reference the field which generated the error."""

    def __init__(self, title=None, description=None, field: str = None, **kwargs):
        super(HTTPBadRequestField, self).__init__(title, description, **kwargs)
        self.field = {field: description}

    def to_dict(self, obj_type=dict):
        result = super(HTTPBadRequestField, self).to_dict(obj_type)
        if self.field is not None:
            result['field'] = self.field
        return result

import yaml
from tastypie.serializers import Serializer

class SafeYAMLSerializer(Serializer):
    def from_yaml(self, content):
        return yaml.safe_load(content)
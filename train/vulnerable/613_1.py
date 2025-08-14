import yaml
from tastypie.serializers import Serializer

class VulnerableYAMLSerializer(Serializer):
    def from_yaml(self, content):
        return yaml.load(content)
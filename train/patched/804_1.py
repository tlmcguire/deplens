from rest_framework import serializers
from .models import User

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email']

from rest_framework import viewsets

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def get_queryset(self):
        depth = self.request.query_params.get('depth', None)
        if depth is not None:
            raise serializers.ValidationError("The 'depth' parameter is not allowed.")
        return super().get_queryset()
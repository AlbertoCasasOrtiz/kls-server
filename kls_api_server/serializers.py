from .models import SetModel
from rest_framework import serializers


class SetSerializer(serializers.ModelSerializer):
    set_name = serializers.CharField(allow_null=False, allow_blank=False)

    class Meta:
        model = SetModel
        fields = ('id', 'set_name')

from django.contrib import admin
from .models import User, SetModel, MovementModel, KeyPointsMovementModel, MovementErrorModel, KeyPointsMovementErrorModel

admin.site.register(User)


# Register your models here.
@admin.register(SetModel)
class SetAdmin(admin.ModelAdmin):
    list_filter = ('set_name',)
    list_display = ('set_name', 'set_description', 'set_template_file')


@admin.register(MovementModel)
class MovementAdmin(admin.ModelAdmin):
    list_filter = ('set', 'movement_name',)
    list_display = ('movement_name',
                    'movement_order',
                    'movement_description',
                    'movement_feedback_message',
                    'movement_start_frame',
                    'movement_end_frame',
                    'set')


@admin.register(KeyPointsMovementModel)
class KeyPointsMovementAdmin(admin.ModelAdmin):
    list_filter = ('movement', 'keypoint_name',)
    list_display = ('keypoint_name', 'movement')


@admin.register(MovementErrorModel)
class MovementErrorAdmin(admin.ModelAdmin):
    list_filter = ('movement', 'movement_name',)
    list_display = ('movement_name',
                    'movement_description',
                    'movement_feedback_message',
                    'movement_start_frame',
                    'movement_end_frame',
                    'movement')


@admin.register(KeyPointsMovementErrorModel)
class KeyPointsMovementErrorAdmin(admin.ModelAdmin):
    list_filter = ('movement_error', 'keypoint_name',)
    list_display = ('keypoint_name', 'movement_error')

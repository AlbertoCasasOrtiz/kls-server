from django.db import models
from django.contrib.auth.models import AbstractUser, Group, Permission


class MediaPipeLandmarks:
    landmarks = ["NOSE",
                 "LEFT_EYE_INNER", "LEFT_EYE", "LEFT_EYE_OUTER",
                 "RIGHT_EYE_INNER", "RIGHT_EYE", "RIGHT_EYE_OUTER",
                 "LEFT_EAR", "RIGHT_EAR",
                 "MOUTH_LEFT", "MOUTH_RIGHT",
                 "LEFT_SHOULDER", "RIGHT_SHOULDER",
                 "LEFT_ELBOW", "RIGHT_ELBOW",
                 "LEFT_WRIST", "RIGHT_WRIST",
                 "LEFT_PINKY", "RIGHT_PINKY",
                 "LEFT_INDEX", "RIGHT_INDEX",
                 "LEFT_THUMB", "RIGHT_THUMB",
                 "LEFT_HIP", "RIGHT_HIP",
                 "LEFT_KNEE", "RIGHT_KNEE",
                 "LEFT_ANKLE", "RIGHT_ANKLE",
                 "LEFT_HEEL", "RIGHT_HEEL",
                 "LEFT_FOOT_INDEX", "RIGHT_FOOT_INDEX"]

    NOSE = landmarks[0]
    LEFT_EYE_INNER = landmarks[1]
    LEFT_EYE = landmarks[2]
    LEFT_EYE_OUTER = landmarks[3]
    RIGHT_EYE_INNER = landmarks[4]
    RIGHT_EYE = landmarks[5]
    RIGHT_EYE_OUTER = landmarks[6]
    LEFT_EAR = landmarks[7]
    RIGHT_EAR = landmarks[8]
    MOUTH_LEFT = landmarks[9]
    MOUTH_RIGHT = landmarks[10]
    LEFT_SHOULDER = landmarks[11]
    RIGHT_SHOULDER = landmarks[12]
    LEFT_ELBOW = landmarks[13]
    RIGHT_ELBOW = landmarks[14]
    LEFT_WRIST = landmarks[15]
    RIGHT_WRIST = landmarks[16]
    LEFT_PINKY = landmarks[17]
    RIGHT_PINKY = landmarks[18]
    LEFT_INDEX = landmarks[19]
    RIGHT_INDEX = landmarks[20]
    LEFT_THUMB = landmarks[21]
    RIGHT_THUMB = landmarks[22]
    LEFT_HIP = landmarks[23]
    RIGHT_HIP = landmarks[24]
    LEFT_KNEE = landmarks[25]
    RIGHT_KNEE = landmarks[26]
    LEFT_ANKLE = landmarks[27]
    RIGHT_ANKLE = landmarks[28]
    LEFT_HEEL = landmarks[29]
    RIGHT_HEEL = landmarks[30]
    LEFT_FOOT_INDEX = landmarks[31]
    RIGHT_FOOT_INDEX = landmarks[32]

    def get_ordered_landmarks_list(self):
        return sorted(self.landmarks)


# Define choices and other classes here.
class ExpertiseLevelIntegerChoices(models.IntegerChoices):
    BEGINNER = 0, "Beginner"
    INTERMEDIATE = 1, "Intermediate"
    ADVANCED = 2, "Advanced"
    EXPERT = 3, "Expert"


class KeyPointsIntegerChoices(models.IntegerChoices):
    NOSE = 0, MediaPipeLandmarks.NOSE
    LEFT_EYE_INNER = 1, MediaPipeLandmarks.LEFT_EYE_INNER
    LEFT_EYE = 2, MediaPipeLandmarks.LEFT_EYE
    LEFT_EYE_OUTER = 3, MediaPipeLandmarks.LEFT_EYE_OUTER
    RIGHT_EYE_INNER = 4, MediaPipeLandmarks.RIGHT_EYE_INNER
    RIGHT_EYE = 5, MediaPipeLandmarks.RIGHT_EYE
    RIGHT_EYE_OUTER = 6, MediaPipeLandmarks.RIGHT_EYE_OUTER
    LEFT_EAR = 7, MediaPipeLandmarks.LEFT_EAR
    RIGHT_EAR = 8, MediaPipeLandmarks.RIGHT_EAR
    MOUTH_LEFT = 9, MediaPipeLandmarks.MOUTH_LEFT
    MOUTH_RIGHT = 10, MediaPipeLandmarks.MOUTH_RIGHT
    LEFT_SHOULDER = 11, MediaPipeLandmarks.LEFT_SHOULDER
    RIGHT_SHOULDER = 12, MediaPipeLandmarks.RIGHT_SHOULDER
    LEFT_ELBOW = 13, MediaPipeLandmarks.LEFT_ELBOW
    RIGHT_ELBOW = 14, MediaPipeLandmarks.RIGHT_ELBOW
    LEFT_WRIST = 15, MediaPipeLandmarks.LEFT_WRIST
    RIGHT_WRIST = 16, MediaPipeLandmarks.RIGHT_WRIST
    LEFT_PINKY = 17, MediaPipeLandmarks.LEFT_PINKY
    RIGHT_PINKY = 18, MediaPipeLandmarks.RIGHT_PINKY
    LEFT_INDEX = 19, MediaPipeLandmarks.LEFT_INDEX
    RIGHT_INDEX = 20, MediaPipeLandmarks.RIGHT_INDEX
    LEFT_THUMB = 21, MediaPipeLandmarks.LEFT_THUMB
    RIGHT_THUMB = 22, MediaPipeLandmarks.RIGHT_THUMB
    LEFT_HIP = 23, MediaPipeLandmarks.LEFT_HIP
    RIGHT_HIP = 24, MediaPipeLandmarks.RIGHT_HIP
    LEFT_KNEE = 25, MediaPipeLandmarks.LEFT_KNEE
    RIGHT_KNEE = 26, MediaPipeLandmarks.RIGHT_KNEE
    LEFT_ANKLE = 27, MediaPipeLandmarks.LEFT_ANKLE
    RIGHT_ANKLE = 28, MediaPipeLandmarks.RIGHT_ANKLE
    LEFT_HEEL = 29, MediaPipeLandmarks.LEFT_HEEL
    RIGHT_HEEL = 30, MediaPipeLandmarks.RIGHT_HEEL
    LEFT_FOOT_INDEX = 31, MediaPipeLandmarks.LEFT_FOOT_INDEX
    RIGHT_FOOT_INDEX = 32, MediaPipeLandmarks.RIGHT_FOOT_INDEX

    @staticmethod
    def get_choice_from_name(name):
        if name == MediaPipeLandmarks.NOSE:
            return KeyPointsIntegerChoices.NOSE
        elif name == MediaPipeLandmarks.LEFT_EYE_INNER:
            return KeyPointsIntegerChoices.LEFT_EYE_INNER
        elif name == MediaPipeLandmarks.LEFT_EYE:
            return KeyPointsIntegerChoices.LEFT_EYE
        elif name == MediaPipeLandmarks.LEFT_EYE_OUTER:
            return KeyPointsIntegerChoices.LEFT_EYE_OUTER
        elif name == MediaPipeLandmarks.RIGHT_EYE_INNER:
            return KeyPointsIntegerChoices.RIGHT_EYE_INNER
        elif name == MediaPipeLandmarks.RIGHT_EYE:
            return KeyPointsIntegerChoices.RIGHT_EYE
        elif name == MediaPipeLandmarks.RIGHT_EYE_OUTER:
            return KeyPointsIntegerChoices.RIGHT_EYE_OUTER
        elif name == MediaPipeLandmarks.LEFT_EAR:
            return KeyPointsIntegerChoices.LEFT_EAR
        elif name == MediaPipeLandmarks.RIGHT_EAR:
            return KeyPointsIntegerChoices.RIGHT_EAR
        elif name == MediaPipeLandmarks.MOUTH_LEFT:
            return KeyPointsIntegerChoices.MOUTH_LEFT
        elif name == MediaPipeLandmarks.MOUTH_RIGHT:
            return KeyPointsIntegerChoices.MOUTH_RIGHT
        elif name == MediaPipeLandmarks.LEFT_SHOULDER:
            return KeyPointsIntegerChoices.LEFT_SHOULDER
        elif name == MediaPipeLandmarks.RIGHT_SHOULDER:
            return KeyPointsIntegerChoices.RIGHT_SHOULDER
        elif name == MediaPipeLandmarks.LEFT_ELBOW:
            return KeyPointsIntegerChoices.LEFT_ELBOW
        elif name == MediaPipeLandmarks.RIGHT_ELBOW:
            return KeyPointsIntegerChoices.RIGHT_ELBOW
        elif name == MediaPipeLandmarks.LEFT_WRIST:
            return KeyPointsIntegerChoices.LEFT_WRIST
        elif name == MediaPipeLandmarks.RIGHT_WRIST:
            return KeyPointsIntegerChoices.RIGHT_WRIST
        elif name == MediaPipeLandmarks.LEFT_PINKY:
            return KeyPointsIntegerChoices.LEFT_PINKY
        elif name == MediaPipeLandmarks.RIGHT_PINKY:
            return KeyPointsIntegerChoices.RIGHT_PINKY
        elif name == MediaPipeLandmarks.LEFT_INDEX:
            return KeyPointsIntegerChoices.LEFT_INDEX
        elif name == MediaPipeLandmarks.RIGHT_INDEX:
            return KeyPointsIntegerChoices.RIGHT_INDEX
        elif name == MediaPipeLandmarks.LEFT_THUMB:
            return KeyPointsIntegerChoices.LEFT_THUMB
        elif name == MediaPipeLandmarks.RIGHT_THUMB:
            return KeyPointsIntegerChoices.RIGHT_THUMB
        elif name == MediaPipeLandmarks.LEFT_HIP:
            return KeyPointsIntegerChoices.LEFT_HIP
        elif name == MediaPipeLandmarks.RIGHT_HIP:
            return KeyPointsIntegerChoices.RIGHT_HIP
        elif name == MediaPipeLandmarks.LEFT_KNEE:
            return KeyPointsIntegerChoices.LEFT_KNEE
        elif name == MediaPipeLandmarks.RIGHT_KNEE:
            return KeyPointsIntegerChoices.RIGHT_KNEE
        elif name == MediaPipeLandmarks.LEFT_ANKLE:
            return KeyPointsIntegerChoices.LEFT_ANKLE
        elif name == MediaPipeLandmarks.RIGHT_ANKLE:
            return KeyPointsIntegerChoices.RIGHT_ANKLE
        elif name == MediaPipeLandmarks.LEFT_HEEL:
            return KeyPointsIntegerChoices.LEFT_HEEL
        elif name == MediaPipeLandmarks.RIGHT_HEEL:
            return KeyPointsIntegerChoices.RIGHT_HEEL
        elif name == MediaPipeLandmarks.LEFT_FOOT_INDEX:
            return KeyPointsIntegerChoices.LEFT_FOOT_INDEX
        elif name == MediaPipeLandmarks.RIGHT_FOOT_INDEX:
            return KeyPointsIntegerChoices.RIGHT_FOOT_INDEX
        else:
            raise LookupError(f"Error: {name} is not a valid keypoint name.")


# Create your models here.
class User(AbstractUser):
    groups = models.ManyToManyField(Group, related_name='auth_users')
    user_permissions = models.ManyToManyField(Permission, related_name='auth_users')

    martial_art = models.CharField(max_length=64, blank=False, null=False)
    expertise_level = models.IntegerField(default=ExpertiseLevelIntegerChoices.BEGINNER,
                                          choices=ExpertiseLevelIntegerChoices.choices)
    last_session = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['username']

    def __str__(self):
        return self.username


class SetModel(models.Model):
    set_name = models.CharField(max_length=64, blank=False, null=False)
    set_description = models.CharField(max_length=256, blank=False, null=False)
    set_template_file = models.FileField(upload_to='static/uploaded/set_templates')
    set_template = models.TextField(blank=False, null=True, default="")

    class Meta:
        ordering = ['set_name', 'set_description']

    def __str__(self):
        return self.set_name


class MovementModel(models.Model):
    movement_name = models.CharField(max_length=64, blank=False, null=False)
    movement_description = models.CharField(max_length=256, blank=False, null=False)
    movement_feedback_message = models.CharField(max_length=256, blank=False, null=False)
    movement_start_frame = models.IntegerField(blank=False, null=False)
    movement_end_frame = models.IntegerField(blank=False, null=False)
    movement_order = models.IntegerField(blank=False, null=False)
    set = models.ForeignKey(SetModel, blank=False, null=False, on_delete=models.CASCADE)

    class Meta:
        ordering = ['set', 'movement_order', 'movement_name']

    def __str__(self):
        return self.set.__str__() + " - " + self.movement_name


class KeyPointsMovementModel(models.Model):
    keypoint_name = models.IntegerField(default=KeyPointsIntegerChoices.NOSE, choices=KeyPointsIntegerChoices.choices)
    movement = models.ForeignKey(MovementModel, blank=False, null=False, on_delete=models.CASCADE)

    class Meta:
        ordering = ['movement', 'keypoint_name']

    def __str__(self):
        return self.movement.__str__() + " - " + KeyPointsIntegerChoices.choices[self.keypoint_name][1]


class MovementErrorModel(models.Model):
    movement_name = models.CharField(max_length=64, blank=False, null=False)
    movement_description = models.CharField(max_length=256, blank=False, null=False)
    movement_feedback_message = models.CharField(max_length=256, blank=False, null=False)
    movement_start_frame = models.IntegerField(blank=False, null=False)
    movement_end_frame = models.IntegerField(blank=False, null=False)
    movement = models.ForeignKey(MovementModel, blank=False, null=False, on_delete=models.CASCADE)

    class Meta:
        ordering = ['movement', 'movement_name']

    def __str__(self):
        return self.movement.__str__() + " - " + self.movement_name


class KeyPointsMovementErrorModel(models.Model):
    keypoint_name = models.IntegerField(default=KeyPointsIntegerChoices.NOSE, choices=KeyPointsIntegerChoices.choices)
    movement_error = models.ForeignKey(MovementErrorModel, blank=False, null=False, on_delete=models.CASCADE)

    class Meta:
        ordering = ['movement_error', 'keypoint_name']

    def __str__(self):
        return self.movement_error.__str__() + " - " + KeyPointsIntegerChoices.choices[self.keypoint_name][1]

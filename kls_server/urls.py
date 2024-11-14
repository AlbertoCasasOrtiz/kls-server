"""
URL configuration for kls_server project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from kls_api_server import views

from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

schema_view = get_schema_view(
    openapi.Info(
        title="KLS Server",
        default_version='v1',
        description="Server for KLS. It allows the interaction between a Display device (e.g., an VR headset of a website) and the mcmarr framework implementing KLS, as well as the database.",
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
    path('', views.Home.as_view(), name="home"),
    path('get_csrf_token/', views.GetCSRFToken.as_view(), name="get_csrf_token"),
    path('test/', views.TestServerView.as_view(), name="test"),
    path('terms_of_use/', views.TermsOfUse.as_view(), name='terms_of_use'),
    path('privacy_policy/', views.PrivacyPolicy.as_view(), name='privacy_policy'),
    path('login/', views.LoginView.as_view(), name='login'),
    path('logout/', views.Logout.as_view(), name='logout'),
    path('logout_app/', views.LogoutApp.as_view(), name='logout_app'),
    path('signup/', views.SignupView.as_view(), name='signup'),
    path('upload_template/', views.UploadTemplateView.as_view(), name='upload_template'),
    path('upload_template/upload/', views.UploadTemplate.as_view(), name='uploaded_template'),
    path('restart_set/', views.RestartSet.as_view(), name='restart_set'),
    path('get_list_sets/', views.GetListSets.as_view(), name='get_list_sets'),
    path('start_set/', views.StartSetView.as_view(), name='start_set'),
    path('info_set/', views.GetSetInfo.as_view(), name='info_set'),
    path('info_set_app/', views.GetSetInfoApp.as_view(), name='info_set_app'),
    path('next_movement/', views.GetNextMovement.as_view(), name='next_movement'),
    path('next_movement_app/', views.GetNextMovementApp.as_view(), name='next_movement_app'),
    path('prepare_capture_movement/', views.PrepareCaptureMovementView.as_view(), name='prepare_capture_movement'),
    path('capture_movement/', views.CaptureMovement.as_view(), name='capture_movement'),
    path('capture_movement_app/', views.CaptureMovementApp.as_view(), name='capture_movement_app'),
    path('model_movement/', views.ModelMovement.as_view(), name='model_movement'),
    path('model_movement_app/', views.ModelMovementApp.as_view(), name='model_movement_app'),
    path('analyze_movement/', views.AnalyzeMovement.as_view(), name='analyze_movement'),
    path('analyze_movement_app/', views.AnalyzeMovementApp.as_view(), name='analyze_movement_app'),
    path('get_response/', views.GetResponse.as_view(), name='get_response'),
    path('get_response_app/', views.GetResponseApp.as_view(), name='get_response_app'),
    path('get_report/', views.GetReport.as_view(), name='get_report'),
    path('regenerate_report/', views.RegenerateReport.as_view(), name='regenerate_report'),
    path('get_report_app/', views.GetReportApp.as_view(), name='get_report_app'),
    path('admin/', admin.site.urls),
    path('get_next_question/', views.GetNextQuestion.as_view()),
    path('get_next_question_app/', views.GetNextQuestionApp.as_view()),
    path('register_wrong_question/', views.RegisterWrongQuestion.as_view()),
    path('register_wrong_question_app/', views.RegisterWrongQuestionApp.as_view()),
    path('register_correct_question/', views.RegisterCorrectQuestion.as_view()),
    path('register_correct_question_app/', views.RegisterCorrectQuestionApp.as_view()),
    path('webcam_stream/', views.WebcamStream.as_view(), name='webcam_stream'),
    path('swagger<format>/', schema_view.with_ui(cache_timeout=0), name='schema-json'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
]

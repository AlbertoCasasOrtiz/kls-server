import os
import ast
import http
import json
import traceback
from datetime import datetime

from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from kls_mcmarr.mcmarr.movement.Movement import Movement
from kls_mcmarr.mcmarr.movement.MovementError import MovementError
from kls_mcmarr.mcmarr.movement.SetOfMovements import SetOfMovements
from rest_framework import views, permissions
from .models import User, SetModel, MovementModel, KeyPointsMovementModel, MovementErrorModel, \
    KeyPointsMovementErrorModel, KeyPointsIntegerChoices
from kls_mcmarr.mcmarr.movement.XmlSetLoader import XmlSetLoader
from .serializers import SetSerializer

from common.utils.utils import get_kls_from_session

import pandas as pd
from django.middleware.csrf import get_token
from django.views.decorators.csrf import csrf_exempt

from kls_mcmarr.kls.kls import KLS

import cv2

from django.http import StreamingHttpResponse


# Test if the server is running and working.
@csrf_exempt
def test(request):
    return JsonResponse({"status": http.HTTPStatus.OK}, status=http.HTTPStatus.OK)


# Get csrf token manually.
@csrf_exempt
def get_csrf_token(request):
    status = http.HTTPStatus.OK
    error_message = ""
    try:
        csrf_token = get_token(request)
    except:
        # printing stack trace
        error_message = "There was an error while obtaining the csrf_token."
        status = http.HTTPStatus.INTERNAL_SERVER_ERROR
        csrf_token = ""
    return JsonResponse({'csrf_token': csrf_token, "status": status, 'error_message': error_message},
                        status=status)


# Get list of loaded sets.
@csrf_exempt
def get_list_sets(request):
    set_names = SetModel.objects.values_list('set_name', flat=True)
    return JsonResponse({'set_names': list(set_names), "status": http.HTTPStatus.OK}, status=http.HTTPStatus.OK)


def webcam_stream(request):
    cap = cv2.VideoCapture(0)
    response = StreamingHttpResponse(generate_frames(cap), content_type="video/mp4; boundary=frame")
    return response


def generate_frames(cap):
    while True:
        ret, frame = cap.read()
        if not ret:
            break
        _, buffer = cv2.imencode('.jpg', frame)
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + buffer.tobytes() + b'\r\n')


def logout_app(request):
    logout(request)
    return JsonResponse({"status": http.HTTPStatus.OK}, status=http.HTTPStatus.OK)


def home(request):
    context = {}
    # Render the HTML template index.html with the data in the context variable
    return render(request, 'home.html', context=context)


def terms_of_use(request):
    context = {}
    # Render the HTML template index.html with the data in the context variable
    return render(request, 'terms_of_use.html', context=context)


def privacy_policy(request):
    context = {}
    # Render the HTML template index.html with the data in the context variable
    return render(request, 'privacy_policy.html', context=context)


def login_view(request):
    # If POST, process message.
    if request.method == 'POST':
        # Get format requested. If browser, this des not exist and default is "". If app, this should be "json".
        format_requested = request.POST.get("format_requested", "")

        # Get username and password.
        username = request.POST.get("username", "")
        password = request.POST.get("password", "")

        # Check presence of username and password.
        if username == "":
            error_message = "Please, insert your username."
            return JsonResponse({"error_message": error_message}, status=http.HTTPStatus.BAD_REQUEST)
        if password == "":
            error_message = "Please, insert your password."
            return JsonResponse({"error_message": error_message}, status=http.HTTPStatus.BAD_REQUEST)

        # Authenticate with provided username and password.
        user = authenticate(request, username=username, password=password)

        # Case format requested "json".
        if format_requested == "json":
            # If authentication was successful, return sessionid.
            if user is not None:
                # Login.
                login(request, user)
                # Return response with generated sessionid for this user.
                return JsonResponse({"sessionid": request.session.session_key}, status=http.HTTPStatus.OK)
            # If authentication was not successful, return error message.
            else:
                error_message = "Username or password incorrect. Please, try again."
                return JsonResponse({"error_message": error_message}, status=http.HTTPStatus.FORBIDDEN)

        # Case browser.
        else:
            # If authentication was successful, login and redirect to home.
            if user is not None:
                login(request, user)
                return redirect('home')
            # If authentication was not successful, return error message.
            else:
                error_message = "Username or password incorrect. Please, try again."
                return render(request, 'login.html', {'error_message': error_message, "status": "error"})
    # If GET, render login page.
    else:
        context = {"status": "success"}
        return render(request, 'login.html', context=context)


def logout_view(request):
    logout(request)
    context = {}
    return render(request, 'logout.html', context=context)


def signup_view(request):
    # If POST, process message.
    if request.method == 'POST':
        format_requested = request.POST.get("format_requested", "")

        # Get username, email and password.
        username = request.POST.get("username", "")
        email = request.POST.get("email", "")
        password = request.POST.get("password", "")

        # Check presence of username, email and password.
        if username == "":
            error_message = "Please, insert your username."
            return JsonResponse({"error_message": error_message}, status=http.HTTPStatus.BAD_REQUEST)
        if email == "":
            error_message = "Please, insert your email."
            return JsonResponse({"error_message": error_message}, status=http.HTTPStatus.BAD_REQUEST)
        if password == "":
            error_message = "Please, insert your password."
            return JsonResponse({"error_message": error_message}, status=http.HTTPStatus.BAD_REQUEST)

        # Case format requested "json".
        if format_requested == "json":
            # Check if username is already taken
            if User.objects.filter(username=username).exists():
                error_message = "Username already exist."
                return JsonResponse({"error_message": error_message}, status=http.HTTPStatus.CONFLICT)
            else:
                # Create a new user with provided information.
                user = User.objects.create_user(username=username, email=email, password=password)

                # If user created, return empty json with no errors. Otherwise, erturn error.
                if user is not None:
                    return JsonResponse({}, status=http.HTTPStatus.OK)
                else:
                    error_message = "There was an error while creating the user."
                    return JsonResponse({"error_message": error_message}, status=http.HTTPStatus.FORBIDDEN)
        else:
            if User.objects.filter(username=username).exists():
                error_message = "Username already exist."
                return render(request, 'signup.html', {'error_message': error_message, "status": "error"})
            else:
                # Create a new user with provided information.
                user = User.objects.create_user(username=username, email=email, password=password)

                # Log the user in
                login(request, user)

                # Redirect to home, since we already signed in.
                return redirect('home')
    # If GET, render login page.
    else:
        return render(request, 'signup.html', {"status": "success"})


def upload_template(request):
    context = {}
    # Render the HTML template index.html with the data in the context variable
    return render(request, 'upload_template.html', context=context)


class UploadTemplate(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        status = 'success'
        error_message = ''

        # Get uploaded file, read it and decode it.
        file_content = request.FILES["file"].read().decode('utf-8')

        # Load set information.
        loader = XmlSetLoader(string=file_content)
        set_of_movements = loader.load_xml_set()

        # Check if the set is already in the database.
        set_count = SetModel.objects.filter(set_name=set_of_movements.get_name()).count()

        if set_count > 0:
            status = 'error'
            error_message = "This set is already in the database. " \
                            "Remove it or change its name if you want to upload it again."
        else:
            # Upload set information to database.
            # Create a row for the set.
            db_set_of_movements = SetModel(set_name=set_of_movements.get_name(),
                                           set_description=set_of_movements.get_description(),
                                           set_template=set_of_movements.get_template(),
                                           set_template_file=request.FILES["file"])
            # Save set row.
            db_set_of_movements.save()

            # Upload movements.
            # Get Set from database.
            set_object = SetModel.objects.get(set_name=set_of_movements.get_name())

            # For each movement...
            for movement in set_of_movements.get_movements():

                # Create a row for the movement.
                db_movement = MovementModel(movement_name=movement.get_name(),
                                            movement_description=movement.get_description(),
                                            movement_feedback_message=movement.get_feedback_message(),
                                            movement_start_frame=movement.get_start_frame(),
                                            movement_end_frame=movement.get_end_frame(),
                                            movement_order=movement.get_order(),
                                            set=set_object)
                # Save movement row.
                db_movement.save()

                # Get movement from database.
                movement_object = MovementModel.objects.filter(set=set_object).get(movement_name=movement.get_name())

                # For each keypoint...
                for keypoint in movement.get_keypoint_names():
                    db_keypoints = KeyPointsMovementModel(keypoint_name=KeyPointsIntegerChoices.get_choice_from_name(keypoint),
                                                          movement=movement_object)
                    # Save keypoints row.
                    db_keypoints.save()

                # For each error...
                for movement_error in movement.get_movement_errors():
                    # Create a row for the movement error.
                    db_movement_error = MovementErrorModel(movement_name=movement_error.get_name(),
                                                           movement_description=movement_error.get_description(),
                                                           movement_feedback_message=movement_error.get_feedback_message(),
                                                           movement_start_frame=movement_error.get_start_frame(),
                                                           movement_end_frame=movement_error.get_end_frame(),
                                                           movement=movement_object)
                    # Save movement error row.
                    db_movement_error.save()

                    # Get movement errorfrom database.
                    movement_error_object = MovementErrorModel.objects.filter(movement=movement_object).get(movement_name=movement_error.get_name())

                    # For each error keypoint...
                    for keypoint_error in movement.get_keypoint_names():
                        db_keypoints_error = KeyPointsMovementErrorModel(keypoint_name=KeyPointsIntegerChoices.get_choice_from_name(keypoint_error),
                                                                         movement_error=movement_error_object)
                        # Save keypoints row.
                        db_keypoints_error.save()

        context = {
            'status': status,
            'error_message': error_message
        }

        return render(request, 'uploaded_template.html', context=context)


class StartSetView(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        set_names = SetModel.objects.values_list('set_name', flat=True)

        context = {
            'set_names': list(set_names)
        }

        return render(request, 'start_set.html', context=context)

    def post(self, request):
        status = 'success'
        error_message = ''

        #  Create new kls instance.
        kls = KLS()

        # kls set where everything is stored.
        kls_set = SetOfMovements(kls.model)

        try:
            # Serialize data.
            serializer = SetSerializer(data=request.data, context={'request': request})
            serializer.is_valid(raise_exception=True)

            # Get set name.
            set_name_search = serializer.validated_data['set_name']

            # Get set database object.
            set_database = SetModel.objects.filter(set_name=set_name_search)[0]

            # Extract information from set object.
            kls_set.set_name(set_database.set_name)
            set_name = set_database.set_name
            set_description = set_database.set_description
            kls_set.set_description(set_description)

            # Extract template and convert into json object.
            if set_database.set_template:
                json_template = json.loads(set_database.set_template)
                kls_set.set_template(json_template)

            # Extract movement objects.
            list_movements = MovementModel.objects.filter(set__set_name=set_name).order_by("movement_order")

            # For each movement, extract information.
            for movement in list_movements:
                kls_movement = Movement()
                kls_movement.set_name(movement.movement_name)
                kls_movement.set_description(movement.movement_description)
                kls_movement.set_feedback_message(movement.movement_feedback_message)
                kls_movement.set_start_frame(movement.movement_start_frame)
                kls_movement.set_end_frame(movement.movement_end_frame)
                kls_movement.set_order(movement.movement_order)

                # Extract keypoints.
                list_keypoints = KeyPointsMovementModel.objects.filter(movement__exact=movement)

                # For each keypoint, extract information.
                for keypoint in list_keypoints:
                    kls_movement.add_keypoint(KeyPointsIntegerChoices.choices[keypoint.keypoint_name][1])

                # Extract movement error objects.
                list_movements_error = MovementErrorModel.objects.filter(movement__exact=movement)

                # For each movement error, extract information.
                for movement_error in list_movements_error:
                    kls_movement_error = MovementError()
                    kls_movement_error.set_name(movement_error.movement_name)
                    kls_movement_error.set_description(movement_error.movement_description)
                    kls_movement_error.set_feedback_message(movement_error.movement_feedback_message)
                    kls_movement_error.set_start_frame(movement_error.movement_start_frame)
                    kls_movement_error.set_end_frame(movement_error.movement_end_frame)

                    # Extract keypoints.
                    list_keypoints_error = KeyPointsMovementErrorModel.objects.filter(
                        movement_error__exact=movement_error)

                    # For each keypoint, extract information.
                    for keypoint_error in list_keypoints_error:
                        kls_movement_error.add_keypoint(
                            KeyPointsIntegerChoices.choices[keypoint_error.keypoint_name][1])

                    # Add movement error to movement.
                    kls_movement.add_movement_error(kls_movement_error)

                # Add movement to set.
                kls_set.add_movement(kls_movement)
        except:
            # printing stack trace
            error_message = "The Set does not exist."
            status = 'error'

        # Set this set as current set in kls. We do this here since we want an empty set if there is an error or the
        # set has not been found.
        kls.set_set_of_movements(kls_set)
        kls.initialize_set()

        # Extract templates.
        templates = {}
        movements_from_template = kls.set_of_movements.get_movements()
        for movement in movements_from_template:
            movement_name = movement.get_name()
            # Modeled because we need it modeled in the same way as the captured movement.
            if kls.set_of_movements.template:
                movement_template = kls.model.model_movement(
                    kls.set_of_movements.get_template_of_movement(movement.get_name()), "template_" + movement_name)
                templates[movement_name] = movement_template.to_json(orient='records')

        # Store the instance to the cache again.
        request.session['kls'] = kls.to_dict()
        request.session['templates'] = templates
        request.session['last_successful'] = True

        context = {
            'status': status,
            'error_message': error_message
        }

        format_requested = request.POST.get("format_requested", "")

        if format_requested == "json":
            return JsonResponse(context, status=http.HTTPStatus.OK)
        else:
            return render(request, 'start_set.html', context=context)


class RestartSet(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        status = 'success'
        error_message = ''

        try:
            #  Get kls instance.
            kls = KLS()

            # Store the instance to the cache again.
            request.session['kls'] = kls.to_dict()
        except:
            # printing stack trace
            error_message = traceback.format_exc()
            status = 'error'

        context = {
            'status': status,
            'error_message': error_message
        }

        return render(request, 'restart_set.html', context=context)


class GetSetInfoApp(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        status = http.HTTPStatus.OK
        set_name = ''
        set_description = ''
        movement_num = 0
        current_movement = -1
        movement_name = []
        error_message = ''

        try:
            #  Get kls instance.
            output_path = request.session.get('output_path', "assets/output/capture/")
            kls = get_kls_from_session(request, output_path)

            # Get current set of movements in mcmarr
            kls_set = kls.get_set_of_movements()

            # Check if the name is empty, if not, continue.
            if kls_set.get_name() != '':
                set_name = kls_set.get_name()
                set_description = kls_set.get_description()
                movement_name = kls_set.get_movement_names()
                movement_num = len(movement_name)
                current_movement = kls.current_movement

                # Create a session uuid name.
                # Generate uuid_name to identify this session.
                current_datetime = datetime.now()
                ordered_string = current_datetime.strftime("%Y-%m-%d-%H-%M-%S")
                session_folder_name = "session - " + str(ordered_string) + "/"

                # Initialize phase implementations.
                output_path = "assets/output/" + request.user.username + "/" + session_folder_name + "/"
                request.session['output_path'] = output_path

                # Create results folder
                os.makedirs("assets/output/" + request.user.username + "/" + session_folder_name + "/")

        except:
            # printing stack trace
            error_message = traceback.format_exc()
            status = http.HTTPStatus.INTERNAL_SERVER_ERROR

        context = {
            'status': status,
            'set_name': set_name,
            'set_description': set_description,
            'movement_num': movement_num,
            'current_movement': current_movement,
            'movement_name': movement_name,
            'error_message': error_message
        }

        return JsonResponse(context, status=http.HTTPStatus.OK)


class GetSetInfo(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        status = 'success'
        set_name = ''
        set_description = ''
        movement_num = 0
        current_movement = -1
        movement_name = []
        error_message = ''

        try:
            #  Get kls instance.
            output_path = request.session.get('output_path', "assets/output/capture/")
            kls = get_kls_from_session(request, output_path)

            # Get current set of movements in mcmarr
            kls_set = kls.get_set_of_movements()

            # Check if the name is empty, if not, continue.
            if kls_set.get_name() != '':
                set_name = kls_set.get_name()
                set_description = kls_set.get_description()
                movement_name = kls_set.get_movement_names()
                movement_num = len(movement_name)
                current_movement = kls.current_movement

                # Create a session uuid name.
                # Generate uuid_name to identify this session.
                current_datetime = datetime.now()
                ordered_string = current_datetime.strftime("%Y-%m-%d-%H-%M-%S")
                session_folder_name = "session - " + str(ordered_string) + "/"

                # Initialize phase implementations.
                output_path = "assets/output/" + request.user.username + "/" + session_folder_name + "/"
                request.session['output_path'] = output_path

                # Create results folder
                os.makedirs("assets/output/" + request.user.username + "/" + session_folder_name + "/")

        except:
            # printing stack trace
            error_message = traceback.format_exc()
            status = 'error'

        context = {
            'status': status,
            'set_name': set_name,
            'set_description': set_description,
            'movement_num': movement_num,
            'current_movement': current_movement,
            'movement_name': movement_name,
            'error_message': error_message
        }

        return render(request, 'get_set_info.html', context=context)


class GetNextMovementApp(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        status = 'success'
        movement_name = ""
        movement_description = ""
        error_message = ''

        try:
            #  Get kls instance.
            output_path = request.session.get('output_path', "assets/output/capture/")
            kls = get_kls_from_session(request, output_path)

            if request.session.get('last_successful', True):
                movement = kls.get_next_movement()
            else:
                movement = kls.get_current_movement()

            if movement is not None:
                movement_name = movement.get_name()
                movement_description = movement.get_description()
            else:
                if kls.condition_finish_session(self):
                    status = "error"
                    error_message = "There was a problem retrieving the next movement."

            # Initialize and save an uuid for this movement.
            expected_movement = kls.set_of_movements.get_movements()[kls.current_movement]
            request.session['uuid_name'] = str(kls.num_iter) + "-" + expected_movement.get_name()

            # Store the instance to the cache again.
            request.session['kls'] = kls.to_dict()
        except:
            # printing stack trace
            error_message = traceback.format_exc()
            status = 'error'

        context = {
            'status': status,
            'movement_name': movement_name,
            'movement_description': movement_description,
            'error_message': error_message
        }

        return JsonResponse(context, status=http.HTTPStatus.OK)


class GetNextMovement(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        status = 'success'
        movement_name = ""
        movement_description = ""
        error_message = ''

        try:
            #  Get kls instance.
            output_path = request.session.get('output_path', "assets/output/capture/")
            kls = get_kls_from_session(request, output_path)

            if request.session.get('last_successful', True):
                movement = kls.get_next_movement()
            else:
                movement = kls.get_current_movement()

            if movement is not None:
                movement_name = movement.get_name()
                movement_description = movement.get_description()
            else:
                if kls.condition_finish_session(self):
                    status = "error"
                    error_message = "There was a problem retrieving the next movement."

            # Initialize and save an uuid for this movement.
            expected_movement = kls.set_of_movements.get_movements()[kls.current_movement]
            request.session['uuid_name'] = str(kls.num_iter) + "-" + expected_movement.get_name()

            # Store the instance to the cache again.
            request.session['kls'] = kls.to_dict()
        except:
            # printing stack trace
            error_message = traceback.format_exc()
            status = 'error'

        context = {
            'status': status,
            'movement_name': movement_name,
            'movement_description': movement_description,
            'error_message': error_message
        }

        return render(request, 'get_next_movement.html', context=context)


def prepare_capture_movement(request):
    context = {}
    # Render the HTML template index.html with the data in the context variable
    return render(request, 'prepare_capture_movement.html', context=context)


class CaptureMovementApp(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        status = 'success'
        error_message = ''

        try:
            #  Get kls instance.
            output_path = request.session.get('output_path', "assets/output/capture/")
            kls = get_kls_from_session(request, output_path)

            # Get uuid for this iteration.
            uuid_name = request.session.get('uuid_name', None)

            # Start capturing movement
            captured_movement = kls.capture.capture_movement(uuid_name=uuid_name)

            # Store captured movement.
            request.session['captured_movement'] = captured_movement.to_json(orient='records')

        except:
            # printing stack trace
            error_message = traceback.format_exc()
            status = 'error'
            print(error_message)

        context = {
            'status': status,
            'error_message': error_message
        }

        return JsonResponse(context, status=http.HTTPStatus.OK)


class CaptureMovement(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        status = 'success'
        error_message = ''

        try:
            #  Get kls instance.
            output_path = request.session.get('output_path', "assets/output/capture/")
            kls = get_kls_from_session(request, output_path)

            # Get uuid for this iteration.
            uuid_name = request.session.get('uuid_name', None)

            # Start capturing movement
            captured_movement = kls.capture.capture_movement(uuid_name=uuid_name)

            # Store captured movement.
            request.session['captured_movement'] = captured_movement.to_json(orient='records')

        except:
            # printing stack trace
            error_message = traceback.format_exc()
            status = 'error'
            print(error_message)

        context = {
            'status': status,
            'error_message': error_message
        }

        return render(request, 'finished_capture_movement.html', context=context)


class ModelMovementApp(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        status = 'success'
        error_message = ''

        try:
            #  Get kls instance.
            output_path = request.session.get('output_path', "assets/output/capture/")
            kls = get_kls_from_session(request, output_path)

            # Get uuid for this iteration.
            uuid_name = request.session.get('uuid_name', None)

            # Get captured movement from session.
            captured_movement = pd.read_json(request.session.get('captured_movement', None))

            # Start model movement
            modeled_movement = kls.model.model_movement(captured_movement, uuid_name)

            # Store modeled movement.
            request.session['modeled_movement'] = modeled_movement.to_json(orient='records')

        except:
            # printing stack trace
            error_message = traceback.format_exc()
            status = 'error'
            print(error_message)

        context = {
            'status': status,
            'error_message': error_message
        }

        return JsonResponse(context, status=http.HTTPStatus.OK)


class ModelMovement(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        status = 'success'
        error_message = ''

        try:
            #  Get kls instance.
            output_path = request.session.get('output_path', "assets/output/capture/")
            kls = get_kls_from_session(request, output_path)

            # Get uuid for this iteration.
            uuid_name = request.session.get('uuid_name', None)

            # Get captured movement from session.
            captured_movement = pd.read_json(request.session.get('captured_movement', None))

            # Start model movement
            modeled_movement = kls.model.model_movement(captured_movement, uuid_name)

            # Store modeled movement.
            request.session['modeled_movement'] = modeled_movement.to_json(orient='records')

        except:
            # printing stack trace
            error_message = traceback.format_exc()
            status = 'error'
            print(error_message)

        context = {
            'status': status,
            'error_message': error_message
        }

        return render(request, 'model_movement.html', context=context)


class AnalyzeMovementApp(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        status = 'success'
        error_message = ''

        try:
            #  Get kls instance.
            output_path = request.session.get('output_path', "assets/output/capture/")
            kls = get_kls_from_session(request, output_path)

            # Get expected movement.
            expected_movement = kls.set_of_movements.get_movements()[kls.current_movement]

            # Get uuid for this iteration.
            uuid_name = request.session.get('uuid_name', None)

            # Extract templates from session in json format.
            templates_json = request.session.get('templates', None)

            # Reconvert templates to pandas dataframes.
            templates = {}
            for key, value in templates_json.items():
                templates[key] = pd.read_json(value)

            # Get modeled movement from session.
            modeled_movement = pd.read_json(request.session.get('modeled_movement', None))

            # Analyze modeled movement.
            movement_finished, analyzed_movement_errors = kls.analyze.analyze_movement(modeled_movement,
                                                                                       expected_movement,
                                                                                       kls.num_iter,
                                                                                       uuid_name)

            # Store analyzed movement name.
            request.session['movement_finished'] = movement_finished
            request.session['analyzed_movement_errors'] = str(analyzed_movement_errors)

        except:
            # printing stack trace
            error_message = traceback.format_exc()
            status = 'error'
            movement_finished = False
            analyzed_movement_errors = []
            print(error_message)

        context = {
            'status': status,
            'movement_finished': movement_finished,
            'analyzed_movement_errors': analyzed_movement_errors,
            'error_message': error_message
        }

        return JsonResponse(context, status=http.HTTPStatus.OK)


class AnalyzeMovement(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        status = 'success'
        error_message = ''

        try:
            #  Get kls instance.
            output_path = request.session.get('output_path', "assets/output/capture/")
            kls = get_kls_from_session(request, output_path)

            # Get expected movement.
            expected_movement = kls.set_of_movements.get_movements()[kls.current_movement]

            # Get uuid for this iteration.
            uuid_name = request.session.get('uuid_name', None)

            # Extract templates from session in json format.
            templates_json = request.session.get('templates', None)

            # Reconvert templates to pandas dataframes.
            templates = {}
            for key, value in templates_json.items():
                templates[key] = pd.read_json(value)

            # Get modeled movement from session.
            modeled_movement = pd.read_json(request.session.get('modeled_movement', None))

            # Analyze modeled movement.
            movement_finished, analyzed_movement_errors = kls.analyze.analyze_movement(modeled_movement,
                                                                                       expected_movement,
                                                                                       kls.num_iter,
                                                                                       uuid_name)

            # Store analyzed movement name.
            request.session['movement_finished'] = movement_finished
            request.session['analyzed_movement_errors'] = str(analyzed_movement_errors)

        except:
            # printing stack trace
            error_message = traceback.format_exc()
            status = 'error'
            movement_finished = None
            analyzed_movement_errors = None
            print(error_message)

        context = {
            'status': status,
            'movement_finished': movement_finished,
            'analyzed_movement_errors': analyzed_movement_errors,
            'error_message': error_message
        }

        return render(request, 'analyze_movement.html', context=context)


class GetResponseApp(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        status = 'success'
        is_last = False
        error_message = ''

        try:
            #  Get kls instance.
            output_path = request.session.get('output_path', "assets/output/capture/")
            kls = get_kls_from_session(request, output_path)

            # Get expected movement.
            expected_movement = kls.set_of_movements.get_movements()[kls.current_movement]

            # Get next movement.
            if kls.current_movement + 1 < len(kls.set_of_movements.get_movements()):
                next_movement = kls.set_of_movements.get_movements()[kls.current_movement + 1]
                next_movement_name = next_movement.get_name()
            else:
                next_movement_name = None
                is_last = True

            # Get analyzed movement name from request.
            movement_finished = request.session.get('movement_finished', None)
            analyzed_movement_errors = ast.literal_eval(request.session.get('analyzed_movement_errors', None))

            # Obtain generated response and if the movement is correct.
            generated_response, is_correct = kls.response.generate_response(movement_finished,
                                                                            analyzed_movement_errors,
                                                                            expected_movement,
                                                                            next_movement_name)

            # Deliver response.
            # kls.response.deliver_response(generated_response)

            # Store errors.
            kls.compiled_errors.append([kls.num_iter, expected_movement.get_name(), analyzed_movement_errors])

            # Update next movement.
            if is_correct:
                request.session['last_successful'] = True
            else:
                request.session['last_successful'] = False

            # Update num. iter.
            kls.num_iter = kls.num_iter + 1

            # Store the instance to the cache again.
            request.session['kls'] = kls.to_dict()

        except:
            # printing stack trace
            error_message = traceback.format_exc()
            status = 'error'
            generated_response = ''
            is_last = False
            is_correct = False
            print(error_message)

        context = {
            'status': status,
            'generated_response': generated_response,
            'is_last': is_last,
            'is_correct': is_correct,
            'error_message': error_message
        }

        return JsonResponse(context, status=http.HTTPStatus.OK)


class GetResponse(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        status = 'success'
        is_last = False
        error_message = ''

        try:
            #  Get kls instance.
            output_path = request.session.get('output_path', "assets/output/capture/")
            kls = get_kls_from_session(request, output_path)

            # Get expected movement.
            expected_movement = kls.set_of_movements.get_movements()[kls.current_movement]

            # Get next movement.
            if kls.current_movement + 1 < len(kls.set_of_movements.get_movements()):
                next_movement = kls.set_of_movements.get_movements()[kls.current_movement + 1]
                next_movement_name = next_movement.get_name()
            else:
                next_movement_name = None
                is_last = True

            # Get analyzed movement name from request.
            movement_finished = request.session.get('movement_finished', None)
            analyzed_movement_errors = ast.literal_eval(request.session.get('analyzed_movement_errors', None))

            # Obtain generated response and if the movement is correct.
            generated_response, is_correct = kls.response.generate_response(movement_finished,
                                                                            analyzed_movement_errors,
                                                                            expected_movement,
                                                                            next_movement_name)

            # Deliver response.
            kls.response.deliver_response(generated_response)

            # Store errors.
            kls.compiled_errors.append([kls.num_iter, expected_movement.get_name(), analyzed_movement_errors])

            # Update next movement.
            if is_correct:
                request.session['last_successful'] = True
            else:
                request.session['last_successful'] = False

            # Update num. iter.
            kls.num_iter = kls.num_iter + 1

            # Store the instance to the cache again.
            request.session['kls'] = kls.to_dict()
        except:
            # printing stack trace
            error_message = traceback.format_exc()
            status = 'error'
            generated_response = ''
            is_last = False
            is_correct = False
            print(error_message)

        context = {
            'status': status,
            'generated_response': generated_response,
            'is_last': is_last,
            'is_correct': is_correct,
            'error_message': error_message
        }

        return render(request, 'get_response.html', context=context)

class GetReport(views.APIView):

    def get(self, request):
        status = 'success'
        error_message = ''

        try:
            #  Get kls instance.
            output_path = request.session.get('output_path', "assets/output/capture/")
            kls = get_kls_from_session(request, output_path)

            # Get session uuid_name.
            output_path = request.session.get('output_path', None)

            generated_reports, score = kls.reports.generate_reports(output_path, "",
                                                             kls.compiled_errors)

        except:
            # printing stack trace
            error_message = traceback.format_exc()
            generated_report_string = ""
            score = 0
            status = 'error'
            generated_reports = ""
            print(error_message)

        context = {
            'status': status,
            'generated_report': generated_reports,
            'score': int(score),
            'error_message': error_message
        }

        return render(request, 'get_report.html', context=context)


class GetReportApp(views.APIView):

    def get(self, request):
        status = 'success'
        generated_report = ''
        error_message = ''

        try:
            # Metrics.
            num_movements = 0

            #  Get kls instance.
            output_path = request.session.get('output_path', "assets/output/capture/")
            kls = get_kls_from_session(request, output_path)

            # # Get current set of movements in mcmarr
            # kls_set = kls.get_set_of_movements()
            #
            # # Get metrics.
            # if kls_set.get_name() != '':
            #     num_movements = len(kls_set.get_movement_names())
            # num_errors = kls.num_iter - num_movements
            #
            # generated_report = f"Num. Movements: {num_movements} \n"
            # generated_report = generated_report + f"Num. Errors: {num_errors} \n"

            # Get session uuid_name.
            output_path = request.session.get('output_path', None)

            generated_report, score = kls.reports.generate_reports(output_path, "",
                                                             kls.compiled_errors)
        except:
            # printing stack trace
            error_message = traceback.format_exc()
            score = 0
            status = 'error'
            generated_report = ''
            print(error_message)

        context = {
            'status': status,
            'generated_report': generated_report,
            'score': score,
            'error_message': error_message
        }

        return JsonResponse(context, status=http.HTTPStatus.OK)

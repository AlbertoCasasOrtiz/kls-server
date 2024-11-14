import os

import cv2
from kls_mcmarr.kls.kls import KLS
from kls_mcmarr.kls.indications.indications import Indications
from kls_mcmarr.kls.capture.capture import Capture
from kls_mcmarr.kls.model.model import Model
from kls_mcmarr.kls.analyze.analyze import Analyze
from kls_mcmarr.kls.response.response import Response
from kls_mcmarr.kls.reports.reports import Reports
from kls_mcmarr.kls.cognitive.Cognitive import Cognitive


def get_kls_from_session(request, output_path):
    kls = KLS.from_dict(request.session.get('kls', None))

    kls = assign_phase_implementations_kls(kls, output_path)

    return kls

def list_ports():
    """
    Test the ports and returns a tuple with the available ports and the ones that are working.
    """
    non_working_ports = []
    dev_port = 0
    working_ports = []
    available_ports = []
    while len(non_working_ports) < 6: # if there are more than 5 non working ports stop the testing.
        camera = cv2.VideoCapture(dev_port)
        if not camera.isOpened():
            non_working_ports.append(dev_port)
            print("Port %s is not working." %dev_port)
        else:
            is_reading, img = camera.read()
            w = camera.get(3)
            h = camera.get(4)
            if is_reading:
                print("Port %s is working and reads images (%s x %s)" %(dev_port,h,w))
                working_ports.append(dev_port)
            else:
                print("Port %s for camera ( %s x %s) is present but does not reads." %(dev_port,h,w))
                available_ports.append(dev_port)
        dev_port +=1
    return available_ports,working_ports,non_working_ports

def assign_phase_implementations_kls(kls, output_path):
    # Create an instance of an implementation of each phase from the MCMARR framework
    indications = Indications()
    # list_ports()
    capture = Capture(capture_mode="camera", camera_num=0, output_path=output_path,
                      formats_to_store=['csv', 'json'], input_video_paths=["None"])
    model = Model(generate_plots=True, output_path=output_path)
    analyze = Analyze(output_path=output_path)
    response = Response()
    reports = Reports()
    cognitive = Cognitive()
    print(os.getcwd())
    cognitive.load_questions("assets/questions/questions.xml")

    # Assign the instances to the KLS object.
    kls.assign_phase_implementations(indications, capture, model, analyze, response, reports, cognitive)

    return kls

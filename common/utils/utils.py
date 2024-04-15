import os

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


def assign_phase_implementations_kls(kls, output_path):
    # Create an instance of an implementation of each phase from the MCMARR framework
    indications = Indications()
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

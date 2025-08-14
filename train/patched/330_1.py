
from ni_measurementlink_service import MeasurementLinkService
from flask import abort, request, make_response

service = MeasurementLinkService()
service.set_https(True)
service.set_certificate_file('certificate.pem')
service.set_key_file('key.pem')

service.start(host='0.0.0.0', port=8080)

@service.route('/sensitive-data', methods=['GET', 'POST'])
def sensitive_data():
    if request.method == 'POST':
        token = request.form.get('csrf_token')
        if not token or not service.csrf.validate_csrf_token(token):
            abort(403)

    if request.headers.get('Origin') != service.base_url:
        abort(403)

    return make_response("This is sensitive data!", 200)
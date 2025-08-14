from ni_measurementlink_service import MeasurementLinkService

service = MeasurementLinkService()

service.start(host='0.0.0.0', port=8080)

@service.route('/sensitive-data')
def sensitive_data():
    return "This is sensitive data!"
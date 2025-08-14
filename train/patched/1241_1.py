def verify_bundle(bundle):

    if bundle['version'] in ('v2', 'v3'):
        integration_time = bundle.get('integrationTime')
        signed_time_source = bundle.get('signedTimeSource')

        if integration_time is not None:
            if signed_time_source is None:
                if not validate_integration_time(integration_time):
                    raise ValueError("Invalid integration time")
            else:
                pass
        else:
            raise ValueError("Missing integration time")


def validate_integration_time(integration_time):
    from datetime import datetime, timedelta
    try:
        time = datetime.fromisoformat(integration_time)
        return (datetime.now(tz=time.tzinfo) - time) < timedelta(hours=24)
    except ValueError:
        return False

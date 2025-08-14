import os
import yaml

def export_pipeline(pipeline, output_format='yaml'):
    s3_credentials = get_s3_credentials_from_secret()

    export_data = {
        'pipeline': pipeline,
        's3_credentials_id': s3_credentials['id']
    }

    if output_format == 'yaml':
        with open('pipeline_export.yaml', 'w') as file:
            yaml.dump(export_data, file)
    elif output_format == 'python_dsl':
        with open('pipeline_export.py', 'w') as file:
            file.write(f"pipeline = {pipeline}\n")
            file.write(f"s3_credentials_id = '{s3_credentials['id']}'\n")

def get_s3_credentials_from_secret():
    return {
        'id': 's3-credentials-secret-id'
    }